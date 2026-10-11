//! Intermediate representation for Kotodama programs.
//!
//! This lowering IR is three-address code with explicit basic-block jumps. It retains deterministic
//! edge assignments as the compiler's de-SSA transport form. Before code generation, [`crate::ssa`]
//! converts it to strict SSA MIR with explicit Phi nodes, verifies dominance and definition
//! uniqueness, and deterministically lowers it back for register allocation.
use super::{
    abi_schema::{json_construction_schema, state_value_kind_for_type, state_value_schema},
    ast::{BinaryOp, PatternBinding, SumVariant, UnaryOp},
    semantic::{
        self, CompilerIntrinsic, Type, TypedBlock, TypedExpr, TypedFunction, TypedItem, TypedParam,
        TypedProgram, TypedStateDecl, TypedStatement,
    },
};
use iroha_data_model::smart_contract::manifest::DynamicAccessHint;
use iroha_model_base::state_path::StatePath;
use kotodama_surface::builtins::{Builtin, BuiltinLowering, PointerConstructor};
use std::collections::{BTreeSet, HashMap, HashSet};

mod sum;
use sum::{emit_sum_value, load_sum_payload, load_sum_tag, sum_layout_for_type};
fn state_map_base_name(expr: &semantic::TypedExpr) -> Option<String> {
    if let semantic::ExprKind::Ident(name) = expr.kind() {
        Some(name.clone())
    } else {
        None
    }
}
#[derive(Clone, Debug)]
struct StateMapSpec {
    key: Type,
    value: Type,
}
fn append_value_word_types(ty: &Type, words: &mut Vec<Type>) {
    match semantic::resolve_struct_type(ty) {
        Type::Struct { fields, .. } if fields.is_empty() => words.push(Type::Unit),
        Type::Tuple(items) if items.is_empty() => words.push(Type::Unit),
        Type::Struct { fields, .. } => {
            for (_, field_ty) in fields.iter() {
                append_value_word_types(field_ty, words);
            }
        }
        Type::Tuple(items) => {
            for item in items {
                append_value_word_types(&item, words);
            }
        }
        // Sums are compiler-owned heap values. Their complete ABI value is
        // one validated raw handle; inactive branches are never flattened
        // into call-table slots or populated with placeholders.
        handle @ (Type::Option(_) | Type::Result(_, _) | Type::List(_, _)) => {
            words.push(handle);
        }
        leaf => words.push(leaf),
    }
}
fn function_value_word_types(ty: &Type) -> Option<Vec<Type>> {
    if !matches!(
        semantic::resolve_struct_type(ty),
        Type::Struct { .. }
            | Type::Tuple(_)
            | Type::Option(_)
            | Type::Result(_, _)
            | Type::List(_, _)
    ) {
        return None;
    }
    let mut words = Vec::new();
    append_value_word_types(ty, &mut words);
    Some(words)
}
fn runtime_value_word_types(ty: &Type) -> Vec<Type> {
    let mut words = Vec::new();
    append_value_word_types(ty, &mut words);
    words
}
fn function_param_word_name(param: &str, index: usize) -> String {
    // `$` is not a source identifier character, so this compiler-owned name
    // cannot collide with a user parameter.
    format!("$abi${param}#{index}")
}
fn collect_state_handle_specs(name: &str, ty: &Type, out: &mut Vec<(String, Type)>) {
    let resolved = semantic::resolve_struct_type(ty);
    out.push((name.to_string(), resolved.clone()));
}
fn lowered_function_params(params: &[TypedParam]) -> Vec<String> {
    let mut lowered = Vec::new();
    for param in params {
        if param.is_state {
            let mut handles = Vec::new();
            collect_state_handle_specs(&param.name, &param.ty, &mut handles);
            lowered.extend(handles.into_iter().map(|(name, _)| name));
        } else if let Some(word_types) = function_value_word_types(&param.ty) {
            lowered.extend(
                word_types
                    .into_iter()
                    .enumerate()
                    .map(|(index, _)| function_param_word_name(&param.name, index)),
            );
        } else {
            lowered.push(param.name.clone());
        }
    }
    lowered
}
/// A virtual register or temporary value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Temp(pub usize);
/// Identifier for a basic block, ordered by its original numeric identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(pub usize);
/// An entire lowered program.
#[derive(Debug, PartialEq)]
pub struct Program {
    pub functions: Vec<Function>,
}
/// A lowered function consisting of basic blocks.
#[derive(Debug, PartialEq)]
pub struct Function {
    pub name: String,
    pub params: Vec<String>,
    pub blocks: Vec<BasicBlock>,
    pub entry: Label,
    pub location: super::ast::SourceLocation,
}
/// A single basic block in a function.
#[derive(Debug, PartialEq)]
pub struct BasicBlock {
    pub label: Label,
    pub instrs: Vec<Instr>,
    pub terminator: Terminator,
}
/// Nominal wide-numeric ABI family selected by semantic typing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideNumericKind {
    /// Signed adaptive-width integer.
    Int,
    /// Exact bounded decimal.
    Decimal,
    /// Nominal non-negative quantity.
    Quantity,
}
/// Rounded exact-decimal operation selected by the typed source method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericRoundOp {
    /// Fused `decimal * decimal / decimal -> decimal`, rounded once.
    DecimalMulDiv,
    /// Fused `quantity * decimal / decimal -> quantity`, rounded once.
    QuantityMulDiv,
    /// `decimal / decimal -> decimal`.
    DecimalDiv,
    /// `quantity / decimal -> quantity`.
    QuantityDiv,
    /// `quantity / quantity -> decimal`.
    QuantityRatio,
}
/// Exact-decimal to integer conversion policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecimalToIntOp {
    /// Discard the fractional component toward zero.
    Truncate,
    /// Apply the explicit rounding mode operand.
    Round,
}
/// Non-control-flow instructions.
#[derive(Debug, PartialEq)]
pub enum Instr {
    /// Source provenance transport; consumed before SSA optimization and code generation.
    /// This marker never becomes an IVM instruction or an optimization barrier.
    Source(Option<crate::source::SourceRange>),
    Const {
        dest: Temp,
        value: i64,
    },
    /// Copy helper used by control-flow joins to materialize merged SSA temps.
    Copy {
        dest: Temp,
        src: Temp,
    },
    /// String literal constant used by pointer‑ABI codegen.
    StringConst {
        dest: Temp,
        value: String,
    },
    Binary {
        dest: Temp,
        op: BinaryOp,
        left: Temp,
        right: Temp,
    },
    /// Explicit modulo-2^512 `int` addition, subtraction, or multiplication.
    WrappingBinary {
        dest: Temp,
        op: BinaryOp,
        left: Temp,
        right: Temp,
    },
    Unary {
        dest: Temp,
        op: UnaryOp,
        operand: Temp,
    },
    /// Explicit modulo-2^512 `int` negation.
    WrappingNeg {
        dest: Temp,
        operand: Temp,
    },
    /// Convert an internal signed IVM scalar into a source `int` pointer.
    IntFromI64 {
        dest: Temp,
        value: Temp,
    },
    /// Convert an internal unsigned IVM scalar into a source `int` pointer.
    IntFromU64 {
        dest: Temp,
        value: Temp,
    },
    /// Fallibly convert a source `int` pointer to an internal signed IVM scalar.
    IntToI64 {
        dest: Temp,
        value: Temp,
    },
    /// Fallibly convert a source `int` pointer to an internal unsigned IVM scalar.
    IntToU64 {
        dest: Temp,
        value: Temp,
    },
    /// Convert between source numeric pointer domains.
    NumericConvert {
        dest: Temp,
        value: Temp,
        source: WideNumericKind,
        destination: WideNumericKind,
    },
    /// Recoverable conversion that preserves the ABI numeric-fault status.
    NumericTryConvert {
        dest: Temp,
        value: Temp,
        source: WideNumericKind,
        destination: WideNumericKind,
    },
    /// Capture the status register immediately after a recoverable numeric syscall.
    NumericStatus {
        dest: Temp,
    },
    /// Checked source numeric negation.
    NumericNeg {
        dest: Temp,
        value: Temp,
        kind: WideNumericKind,
    },
    /// Numeric arithmetic using typed numeric pointer payloads.
    NumericBinary {
        dest: Temp,
        op: BinaryOp,
        left: Temp,
        right: Temp,
        left_kind: WideNumericKind,
        right_kind: WideNumericKind,
        result_kind: WideNumericKind,
    },
    /// Rounded numeric division with an explicit scale and rounding tag.
    NumericRound {
        dest: Temp,
        dividend: Temp,
        /// Present for a fused multiplication/division operation.
        multiplier: Option<Temp>,
        divisor: Temp,
        scale: Temp,
        mode: Temp,
        op: NumericRoundOp,
        result_kind: WideNumericKind,
    },
    /// Convert a decimal pointer to an integer pointer with an explicit policy.
    DecimalToInt {
        dest: Temp,
        value: Temp,
        mode: Option<Temp>,
        op: DecimalToIntOp,
    },
    /// Numeric comparison using typed numeric pointer payloads (result is 0/1).
    NumericCompare {
        dest: Temp,
        op: BinaryOp,
        left: Temp,
        right: Temp,
        kind: WideNumericKind,
    },
    /// ABI helper syscall that accepts already-validated pointer-ABI operands directly.
    DirectHelperSyscall {
        dest: Temp,
        syscall: u32,
        args: Vec<Temp>,
    },
    Min {
        dest: Temp,
        a: Temp,
        b: Temp,
    },
    Max {
        dest: Temp,
        a: Temp,
        b: Temp,
    },
    Abs {
        dest: Temp,
        src: Temp,
    },
    DivCeil {
        dest: Temp,
        num: Temp,
        denom: Temp,
    },
    Gcd {
        dest: Temp,
        a: Temp,
        b: Temp,
    },
    Mean {
        dest: Temp,
        a: Temp,
        b: Temp,
    },
    Isqrt {
        dest: Temp,
        src: Temp,
    },
    /// Load the value of a variable.
    LoadVar {
        dest: Temp,
        name: String,
    },
    Poseidon2 {
        dest: Temp,
        a: Temp,
        b: Temp,
    },
    Poseidon6 {
        dest: Temp,
        args: [Temp; 6],
    },
    Pubkgen {
        dest: Temp,
        src: Temp,
    },
    Valcom {
        dest: Temp,
        value: Temp,
        blind: Temp,
    },
    /// Full-width commitment over two opaque typed private numeric TLVs.
    PrivateNumericValcom {
        dest: Temp,
        value: Temp,
        blind: Temp,
    },
    /// Compute SM3 hash of a Blob pointer and return the resulting Blob pointer.
    Sm3Hash {
        dest: Temp,
        message: Temp,
    },
    /// Compute SHA-256 hash of a Blob pointer and return the resulting Blob pointer.
    Sha256Hash {
        dest: Temp,
        message: Temp,
    },
    /// Compute SHA3-256 hash of a Blob pointer and return the resulting Blob pointer.
    Sha3Hash {
        dest: Temp,
        message: Temp,
    },
    /// Compute Blake2b-256 hash of a Blob pointer and return the resulting Blob pointer.
    Blake2b256Hash {
        dest: Temp,
        message: Temp,
    },
    /// Compute Keccak-256 hash of a Blob pointer and return the resulting Blob pointer.
    Keccak256Hash {
        dest: Temp,
        message: Temp,
    },
    /// Compute Iroha's canonical ledger hash of a Blob pointer and return the resulting Blob pointer.
    IrohaHash {
        dest: Temp,
        message: Temp,
    },
    /// Verify an SM2 signature (message, signature, public key, optional distid) returning a bool.
    Sm2Verify {
        dest: Temp,
        message: Temp,
        signature: Temp,
        public_key: Temp,
        distid: Option<Temp>,
    },
    /// Verify a signature (message, signature, public key, scheme code) returning a bool.
    VerifySignature {
        dest: Temp,
        message: Temp,
        signature: Temp,
        public_key: Temp,
        scheme: Temp,
    },
    /// SM4-GCM seal: key, nonce, aad, plaintext -> ciphertext||tag blob.
    Sm4GcmSeal {
        dest: Temp,
        key: Temp,
        nonce: Temp,
        aad: Temp,
        plaintext: Temp,
    },
    /// SM4-GCM open: key, nonce, aad, ciphertext||tag -> plaintext (or 0 on failure).
    Sm4GcmOpen {
        dest: Temp,
        key: Temp,
        nonce: Temp,
        aad: Temp,
        ciphertext_and_tag: Temp,
    },
    /// SM4-CCM seal: key, nonce, aad, plaintext, optional tag length -> ciphertext||tag blob.
    Sm4CcmSeal {
        dest: Temp,
        key: Temp,
        nonce: Temp,
        aad: Temp,
        plaintext: Temp,
        tag_len: Option<Temp>,
    },
    /// SM4-CCM open: key, nonce, aad, ciphertext||tag, optional tag length -> plaintext blob (or 0).
    Sm4CcmOpen {
        dest: Temp,
        key: Temp,
        nonce: Temp,
        aad: Temp,
        ciphertext_and_tag: Temp,
        tag_len: Option<Temp>,
    },
    /// Register an asset definition with its display name and the
    /// `ivm_registration` numeric-spec and mintability words.
    RegisterAsset {
        asset: Temp,
        name: Temp,
        spec: Temp,
        mintable: Temp,
    },
    /// Call the scoped `transfer_asset` syscall with from, to, asset, amount and dataspace parameters.
    TransferAsset {
        from: Temp,
        to: Temp,
        asset: Temp,
        amount: Temp,
        dataspace: Temp,
    },
    /// Add one transfer entry to the active FASTPQ transfer batch.
    TransferBatchAsset {
        from: Temp,
        to: Temp,
        asset: Temp,
        amount: Temp,
    },
    /// Open and fund a native asset escrow.
    EscrowOpenOffer {
        escrow: Temp,
        asset: Temp,
        amount: Temp,
        evidence_hashes: Option<Temp>,
    },
    /// Accept a native asset escrow.
    EscrowAccept {
        escrow: Temp,
    },
    /// Mark escrow off-chain payment as sent.
    EscrowMarkPaymentSent {
        escrow: Temp,
    },
    /// Release a paid escrow.
    EscrowRelease {
        escrow: Temp,
    },
    /// Cancel an escrow before payment is marked.
    EscrowCancel {
        escrow: Temp,
    },
    /// Open an escrow dispute.
    EscrowOpenDispute {
        escrow: Temp,
        evidence_hashes: Option<Temp>,
    },
    /// Resolve a disputed escrow with a buyer/seller split.
    EscrowResolveDispute {
        escrow: Temp,
        buyer_amount: Temp,
        seller_amount: Temp,
        evidence_hashes: Option<Temp>,
    },
    /// Begin a FASTPQ transfer batch scope.
    TransferBatchBegin,
    /// End the current FASTPQ transfer batch scope.
    TransferBatchEnd,
    /// Call the `mint_asset` syscall with account, asset and amount parameters.
    MintAsset {
        account: Temp,
        asset: Temp,
        amount: Temp,
    },
    /// Call the `burn_asset` syscall with account, asset and amount parameters.
    BurnAsset {
        account: Temp,
        asset: Temp,
        amount: Temp,
    },
    AssertEq {
        left: Temp,
        right: Temp,
    },
    /// Assert that a boolean condition holds.
    Assert {
        cond: Temp,
    },
    /// Abort execution with a stable seiyaku error code if `cond` is non-zero.
    ///
    /// This is a non-ZK assertion primitive intended for fast on-chain checks.
    AbortIf {
        cond: Temp,
        descriptor: Temp,
        code: Temp,
    },
    /// Log an info message (development only).
    Info {
        msg: Temp,
    },
    /// Debug-print a raw integer value.
    DebugPrint {
        value: Temp,
    },
    /// Debug-log a Json/Blob/NoritoBytes TLV pointer.
    DebugLog {
        payload: Temp,
    },
    /// Allocate a new map (heap allocation of 16 bytes) and return its pointer in `dest`.
    MapNew {
        dest: Temp,
    },
    /// Build a typed pointer from a string temp at compile/runtime.
    /// Codegen maps this to a data literal when `src` originates from `StringConst`.
    PointerFromString {
        dest: Temp,
        kind: DataRefKind,
        src: Temp,
    },
    /// Get from map: dest = map[key]
    MapGet {
        dest: Temp,
        map: Temp,
        key: Temp,
    },
    /// Load both key and value from a minimal single-bucket map layout.
    /// Layout: key at [0..8), value at [8..16) from the base pointer.
    MapLoadPair {
        dest_key: Temp,
        dest_val: Temp,
        map: Temp,
        offset: i16,
    },
    /// Set map[key] = value
    MapSet {
        map: Temp,
        key: Temp,
        value: Temp,
    },
    /// Load a 64-bit value from memory at [base + imm].
    Load64Imm {
        dest: Temp,
        base: Temp,
        imm: i16,
    },
    /// Load a 64-bit value from an already-computed memory address.
    Load64 {
        dest: Temp,
        address: Temp,
    },
    /// Store a 64-bit value to memory at `[base + imm]`.
    ///
    /// Bounded collection lowering uses this primitive to initialise and
    /// mutate its single contiguous compiler-owned allocation. The offset is
    /// expressed in bytes and code generation expands addresses outside the
    /// instruction immediate range without changing observable behaviour.
    Store64Imm {
        base: Temp,
        imm: i16,
        value: Temp,
    },
    /// Store a 64-bit value to an already-computed memory address.
    Store64 {
        address: Temp,
        value: Temp,
    },
    /// Pack multiple scalar temps into a tuple value represented by `dest`.
    /// Codegen treats this as metadata; no code is emitted.
    TuplePack {
        dest: Temp,
        items: Vec<Temp>,
    },
    /// Extract the `index`-th field from a tuple temp into `dest`.
    TupleGet {
        dest: Temp,
        tuple: Temp,
        index: usize,
    },
    /// Host helper: create one NFT per known account (sample convenience).
    CreateNftsForAllUsers,
    /// Host helper: set SmartContract execution depth parameter.
    SetExecutionDepth {
        value: Temp,
    },
    /// Host helper: set logical vector length (SETVL immediate).
    SetVl {
        value: Temp,
    },
    /// Call a user-defined function by name with positional arguments.
    /// Arguments and the optional result use the caller-owned V1 word tables.
    Call {
        callee: String,
        args: Vec<Temp>,
        dest: Option<Temp>,
    },
    /// Call a user-defined function returning multiple scalar values.
    /// The callee writes results into the caller-owned V1 result word table.
    /// Codegen loads its initialized words into `dests` in order.
    CallMulti {
        callee: String,
        args: Vec<Temp>,
        dests: Vec<Temp>,
    },
    /// Host helper: set account detail (pointer-ABI).
    /// Accepts pointer temps produced by `account_id/name/json` builtins.
    SetAccountDetail {
        account: Temp,
        key: Temp,
        value: Temp,
    },
    /// Create an NFT with given id and owner.
    CreateNft {
        nft: Temp,
        owner: Temp,
    },
    /// Set JSON metadata for an NFT key.
    SetNftData {
        nft: Temp,
        key: Temp,
        json: Temp,
    },
    /// Burn an NFT by id.
    BurnNft {
        nft: Temp,
    },
    /// Transfer an NFT from one account to another.
    TransferNft {
        from: Temp,
        nft: Temp,
        to: Temp,
    },
    /// Register a Domain by id.
    RegisterDomain {
        domain: Temp,
    },
    /// Register an account by id.
    RegisterAccount {
        account: Temp,
    },
    /// Add a JSON-encoded PublicKey signatory to an account.
    AddSignatory {
        account: Temp,
        signatory: Temp,
    },
    /// Remove a JSON-encoded PublicKey signatory from an account.
    RemoveSignatory {
        account: Temp,
        signatory: Temp,
    },
    /// Set the non-zero multisig quorum for an account.
    SetAccountQuorum {
        account: Temp,
        quorum: Temp,
    },
    /// Unregister a Domain by id.
    UnregisterDomain {
        domain: Temp,
    },
    /// Unregister an Asset Definition by id.
    UnregisterAsset {
        asset: Temp,
    },
    /// Unregister an Account by id.
    UnregisterAccount {
        account: Temp,
    },
    /// Register a peer by JSON payload.
    RegisterPeer {
        json: Temp,
    },
    /// Unregister a peer by JSON payload.
    UnregisterPeer {
        json: Temp,
    },
    /// Create a trigger from JSON spec.
    CreateTrigger {
        json: Temp,
    },
    /// Remove a trigger by name.
    RemoveTrigger {
        name: Temp,
    },
    /// Enable/disable a trigger by name.
    SetTriggerEnabled {
        name: Temp,
        enabled: Temp,
    },
    /// Grant a permission token (Name or Json) to an account.
    GrantPermission {
        account: Temp,
        token: Temp,
    },
    /// Revoke a permission token (Name or Json) from an account.
    RevokePermission {
        account: Temp,
        token: Temp,
    },
    /// Grant an instance permission capability for the executing contract address.
    GrantContractPermission {
        account: Temp,
        permission: Temp,
    },
    /// Revoke an instance permission capability for the executing contract address.
    RevokeContractPermission {
        account: Temp,
        permission: Temp,
    },
    /// Create a role with a JSON permission set.
    CreateRole {
        name: Temp,
        json: Temp,
    },
    /// Delete a role by name.
    DeleteRole {
        name: Temp,
    },
    /// Grant a role to an account.
    GrantRole {
        account: Temp,
        name: Temp,
    },
    /// Revoke a role from an account.
    RevokeRole {
        account: Temp,
        name: Temp,
    },
    /// Transfer a Domain to a new owner account.
    TransferDomain {
        domain: Temp,
        to: Temp,
    },
    /// A typed data reference to be placed in the data section and accessed via the pointer-ABI.
    /// The compiler will emit a load from the literal table into a register, yielding a pointer to
    /// a len-prefixed Norito blob of the encoded value.
    DataRef {
        dest: Temp,
        kind: DataRefKind,
        value: String,
    },
    /// Load current authority AccountId pointer into `dest` (host-provided).
    GetAuthority {
        dest: Temp,
    },
    /// Load current authority AccountId pointer through the extended sysvar surface.
    SysvarAuthority {
        dest: Temp,
    },
    /// Load the current trusted host time in unix milliseconds into `dest`.
    CurrentTimeMs {
        dest: Temp,
    },
    /// Load the current trusted host block height into `dest`.
    BlockHeight {
        dest: Temp,
    },
    /// Load the current trusted host block time in unix milliseconds into `dest`.
    BlockTimeMs {
        dest: Temp,
    },
    /// Load the current chain identifier Blob pointer into `dest`.
    ChainId {
        dest: Temp,
    },
    /// Load the current contract address NoritoBytes pointer into `dest`.
    ContractAddress {
        dest: Temp,
    },
    /// Load the current entrypoint name Blob pointer into `dest`.
    Entrypoint {
        dest: Temp,
    },
    /// Resolve a canonical account alias string to the current AccountId.
    ResolveAccountAlias {
        dest: Temp,
        alias: Temp,
    },
    /// Load the host-provided canonical public argument record (`NoritoBytes*`).
    GetTriggerEvent {
        dest: Temp,
    },
    /// Load an arbitrary host-provided public input TLV by Name key.
    GetPublicInput {
        dest: Temp,
        key: Temp,
    },
    /// Typed invocation of one authenticated public method through A9.
    CallContract {
        view: bool,
        dests: Vec<Temp>,
        contract: Temp,
        binding: Temp,
        payload: Temp,
        argument_words: usize,
    },
    /// Test-only runtime call; no actor selects the current caller.
    InvokeEntrypointAs {
        dest: Option<Temp>,
        actor: Option<Temp>,
        entrypoint: Temp,
        payload: Temp,
        argument_words: usize,
    },
    /// Test-only runtime call with multiple return values and an optional fixture actor.
    InvokeEntrypointAsMulti {
        dests: Vec<Temp>,
        actor: Option<Temp>,
        entrypoint: Temp,
        payload: Temp,
        argument_words: usize,
    },
    /// Test-only assertion that a named actor's runtime entrypoint call rejects.
    ExpectRejectAs {
        actor: Temp,
        entrypoint: Temp,
        payload: Temp,
        argument_words: usize,
        expectation: Temp,
    },
    /// Test-only actor registry lookup helpers.
    ActorAccount {
        dest: Temp,
        actor: Temp,
    },
    ActorPublicKey {
        dest: Temp,
        actor: Temp,
    },
    ActorSign {
        dest: Temp,
        actor: Temp,
        message: Temp,
    },
    /// ZK verify syscalls with NoritoBytes TLV pointer in r10.
    ZkVerify {
        /// Syscall number (0x60..0x63)
        number: u32,
        /// Temp holding pointer to NoritoBytes TLV (INPUT)
        payload: Temp,
    },
    /// Self-reported execution summary as NoritoBytes returned by the host.
    ExecutionSummary {
        dest: Temp,
    },
    /// Grow VM heap by `bytes`, returning the new heap limit.
    GrowHeap {
        dest: Temp,
        bytes: Temp,
    },
    /// Write Merkle path for raw VM memory address to raw memory buffer.
    GetMerklePath {
        dest: Temp,
        address: Temp,
        output: Temp,
        root_output: Option<Temp>,
    },
    /// Write compact Merkle proof for raw VM memory address to raw memory buffer.
    GetMerkleCompact {
        dest: Temp,
        address: Temp,
        output: Temp,
        max_depth: Option<Temp>,
        root_output: Option<Temp>,
    },
    /// Write compact Merkle proof for register leaf to raw memory buffer.
    GetRegisterMerkleCompact {
        dest: Temp,
        register_index: Temp,
        output: Temp,
        max_depth: Option<Temp>,
        root_output: Option<Temp>,
    },
    /// Generic OpenVerify proof verification returning r10 = 0/1.
    VerifyProof {
        dest: Temp,
        payload: Temp,
    },
    /// Operation-specific bridge to SMARTCONTRACT_EXECUTE_INSTRUCTION.
    VendorExecuteInstruction {
        payload: Temp,
        kind: VendorInstructionKind,
    },
    /// Vendor bridge: SMARTCONTRACT_EXECUTE_QUERY with NoritoBytes `QueryRequest` in r10.
    VendorExecuteQuery {
        dest: Temp,
        payload: Temp,
    },
    /// Extended query bridge: QUERY_EXECUTE_NORITO with NoritoBytes `QueryRequest` in r10.
    QueryExecuteNorito {
        dest: Temp,
        payload: Temp,
    },
    /// Specialist byte-returning query helper retained outside the five V1 projected core families.
    QueryGet {
        dest: Temp,
        key: Temp,
        syscall: u32,
    },
    /// Typed singular core query selected by a stable V1 entity tag.
    CoreQueryGet {
        dest: Temp,
        key: Temp,
        entity: ivm_abi::core_query::CoreQueryEntityTagV1,
    },
    /// Typed plural core query selected by a stable V1 entity tag.
    CoreQueryPage {
        /// Raw `List<View, 64>` handle returned in syscall register r10.
        items_dest: Temp,
        /// Raw `Option<int>` next-offset handle returned in syscall register r11.
        next_offset_dest: Temp,
        /// Optional exact owner filter, accepted only for Asset pages.
        account: Option<Temp>,
        entity: ivm_abi::core_query::CoreQueryEntityTagV1,
        offset: Temp,
        limit: Temp,
    },
    /// Host balance query: r10 = &AccountId, r11 = &AssetDefinitionId; returns a Quantity pointer.
    GetAccountBalance {
        dest: Temp,
        account: Temp,
        asset: Temp,
    },
    /// Allocate `bytes` on the VM heap, returning the raw heap pointer.
    Alloc {
        dest: Temp,
        bytes: Temp,
    },
    /// Read a host-provided private input by numeric index.
    GetPrivateInput {
        dest: Temp,
        index: Temp,
        kind: ivm_abi::private_input::PrivateInputKindV1,
    },
    /// Commit the VM OUTPUT region to the host.
    CommitOutput,
    /// Smart-contract lifecycle governance/runtime helper with NoritoBytes request in r10.
    SmartContractLifecycle {
        payload: Temp,
        syscall: u32,
    },
    /// Read recent ZK roots with a NoritoBytes request in r10.
    ZkRootsGet {
        dest: Temp,
        payload: Temp,
    },
    /// Read finalized ZK vote tally with a NoritoBytes request in r10.
    ZkVoteGetTally {
        dest: Temp,
        payload: Temp,
    },
    /// Read the exact unsigned epoch in r10; zero means no seed, otherwise Blob.
    VrfEpochSeed {
        dest: Temp,
        epoch: Temp,
    },
    /// Subscription billing helper using trigger context.
    SubscriptionBill,
    /// Subscription usage recorder using trigger args.
    SubscriptionRecordUsage,
    /// Durable state get: r10 = &NoritoBytes(StatePath); returns r10 = &NoritoBytes into dest.
    StateGet {
        dest: Temp,
        path: Temp,
    },
    /// Durable state set: r10 = &NoritoBytes(StatePath); r11 = &NoritoBytes value.
    StateSet {
        path: Temp,
        value: Temp,
    },
    /// Durable state delete: r10 = &NoritoBytes(StatePath).
    StateDel {
        path: Temp,
    },
    /// Bounded durable-state scan. The four results are the selected paths,
    /// continuation cursor (or zero), live count, and examined candidate count.
    StateScan {
        page: Temp,
        next: Temp,
        count: Temp,
        examined: Temp,
        base: Temp,
        after: Temp,
        limit: Temp,
        /// Exact declared-map provenance; every scan examines at most 64 candidates.
        dynamic_access_hint: DynamicAccessHint,
    },
    /// Decode a canonical map key from a `Vec<StatePath>` scan result.
    /// The declared map base remains a `Name`.
    StateMapKeyAt {
        dest: Temp,
        page: Temp,
        base: Temp,
        index: Temp,
    },
    /// Encode a compiler-flattened aggregate state value using a schema literal.
    StateValueEncode {
        dest: Temp,
        schema: Temp,
        words: Vec<Temp>,
    },
    /// Durable state key presence: r10 = &NoritoBytes(StatePath); returns present flag in dest.
    StateHas {
        dest: Temp,
        path: Temp,
    },
    /// Durable state value payload length: r10 = &NoritoBytes(StatePath); returns length in dest.
    StateLen {
        dest: Temp,
        path: Temp,
    },
    /// Durable state key count for prefix: r10 = &NoritoBytes(StatePath); returns total in dest.
    StateCount {
        dest: Temp,
        prefix: Temp,
    },
    /// Convert a declared/runtime `Name` root into framed `StatePath` bytes.
    StatePathFromName {
        dest: Temp,
        name: Temp,
    },
    /// Build framed, schema-bound `StatePath` bytes from a declared `Name` base
    /// and canonical schema-bound key-record bytes.
    PathMapKeyNorito {
        dest: Temp,
        base: Temp,
        key_blob: Temp,
    },
    /// Encode a pointer-ABI value into NoritoBytes via host.
    PointerToNorito {
        dest: Temp,
        value: Temp,
    },
    /// Decode NoritoBytes into a pointer-ABI value via host.
    PointerFromNorito {
        dest: Temp,
        blob: Temp,
        kind: DataRefKind,
    },
    /// Encode JSON (&Json) to NoritoBytes via host
    JsonEncode {
        dest: Temp,
        json: Temp,
    },
    /// Decode NoritoBytes to &Json via host
    JsonDecode {
        dest: Temp,
        blob: Temp,
    },
    /// Return the payload length of an arbitrary pointer-ABI TLV.
    TlvLen {
        dest: Temp,
        value: Temp,
    },
    /// Construct an empty Json object.
    JsonObject {
        dest: Temp,
    },
    /// Insert or replace an integer field in a Json object.
    JsonSetInt {
        dest: Temp,
        json: Temp,
        key: Temp,
        value: Temp,
    },
    /// Insert or replace an AccountId field in a Json object.
    JsonSetAccountId {
        dest: Temp,
        json: Temp,
        key: Temp,
        value: Temp,
    },
    /// JSON getter returning one active-only typed numeric `Option<T>` handle.
    JsonGetNumeric {
        dest: Temp,
        json: Temp,
        key: Temp,
        kind: WideNumericKind,
    },
    /// JSON getter returning one active-only `Option<Json>` handle.
    JsonGetJson {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<Name>` handle.
    JsonGetName {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<AccountId>` handle.
    JsonGetAccountId {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<AssetDefinitionId>` handle.
    JsonGetAssetDefinitionId {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<NftId>` handle.
    JsonGetNftId {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<bytes>` handle.
    JsonGetBlobHex {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<string>` handle.
    JsonGetString {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// JSON getter returning one active-only `Option<bool>` handle.
    JsonGetBool {
        dest: Temp,
        json: Temp,
        key: Temp,
    },
    /// Decode Name from NoritoBytes via host
    NameDecode {
        dest: Temp,
        blob: Temp,
    },
    /// Schema encode: (&Name schema, &Json) -> &NoritoBytes
    SchemaEncode {
        dest: Temp,
        schema: Temp,
        json: Temp,
    },
    /// Schema decode: (&Name schema, &NoritoBytes) -> &Json
    SchemaDecode {
        dest: Temp,
        schema: Temp,
        blob: Temp,
    },
    /// Fetch schema metadata as Json: (&Name schema) -> &Json {id, version}
    SchemaInfo {
        dest: Temp,
        schema: Temp,
    },
    /// Build a Norito-encoded SubmitBallot InstructionBox in data section and return Blob pointer
    BuildSubmitBallotInline {
        dest: Temp,
        election_id: Temp,
        ciphertext: Temp,
        nullifier: Temp,
        backend: Temp,
        proof: Temp,
        vk: Temp,
    },
    /// Compare two pointer-ABI values for deep equality by content.
    PointerEq {
        dest: Temp,
        left: Temp,
        right: Temp,
    },
    /// Verify a VRF proof and return the output Blob pointer (or 0).
    VrfVerify {
        dest: Temp,
        request: Temp,
    },
    /// Batch VRF verification returning a NoritoBytes vector of outputs (or 0).
    VrfVerifyBatch {
        dest: Temp,
        batch: Temp,
    },
    /// Begin an AXT envelope with descriptor pointer in r10.
    AxtBegin {
        descriptor: Temp,
    },
    /// Record a dataspace touch manifest (optional manifest pointer in r11).
    AxtTouch {
        dsid: Temp,
        manifest: Option<Temp>,
    },
    /// Stage one exact issuer-signed anchored-spend wire in the active AXT.
    StageAnchoredSpend {
        spend: Temp,
    },
    /// Attach or clear a dataspace proof for the active AXT.
    VerifyDsProof {
        dsid: Temp,
        proof: Option<Temp>,
    },
    /// Commit the active AXT envelope.
    AxtCommit,
    /// Execute a Soracloud runtime host operation with request pointer in r10.
    SoracloudHostCall {
        dest: Temp,
        request: Temp,
        syscall: u32,
    },
}
/// Instruction kind authorized by the tagged smart-contract instruction bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorInstructionKind {
    /// Governance `SubmitBallot`.
    SubmitBallot,
}
/// Kinds of typed data references supported by the pointer-ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataRefKind {
    Account,
    AssetDef,
    Name,
    Json,
    NftId,
    AssetId,
    Domain,
    Blob,
    /// Raw NoritoBytes TLV payload (pointer-ABI), distinct from generic Blob.
    NoritoBytes,
    DataSpaceId,
    AxtDescriptor,
    AxtAnchoredSpendV1,
    ProofBlob,
    SoracloudRequest,
    SoracloudResponse,
    /// Canonical signed adaptive-width integer.
    Int,
    /// Canonical exact decimal.
    Decimal,
    /// Canonical non-negative quantity.
    Quantity,
}
fn pointer_kind_for_type(ty: &Type) -> Option<DataRefKind> {
    match semantic::resolve_struct_type(ty) {
        Type::AccountId => Some(DataRefKind::Account),
        Type::AssetDefinitionId => Some(DataRefKind::AssetDef),
        Type::AssetId => Some(DataRefKind::AssetId),
        Type::DomainId => Some(DataRefKind::Domain),
        Type::NftId => Some(DataRefKind::NftId),
        Type::Name => Some(DataRefKind::Name),
        Type::DataSpaceId => Some(DataRefKind::DataSpaceId),
        Type::AxtDescriptor => Some(DataRefKind::AxtDescriptor),
        Type::AxtAnchoredSpendV1 => Some(DataRefKind::AxtAnchoredSpendV1),
        Type::ProofBlob => Some(DataRefKind::ProofBlob),
        Type::SoracloudRequest => Some(DataRefKind::SoracloudRequest),
        Type::SoracloudResponse => Some(DataRefKind::SoracloudResponse),
        Type::Int => Some(DataRefKind::Int),
        Type::Decimal => Some(DataRefKind::Decimal),
        Type::Quantity => Some(DataRefKind::Quantity),
        Type::String | Type::Bytes | Type::ContractRef(_) => Some(DataRefKind::Blob),
        Type::StateCursor(_) => Some(DataRefKind::NoritoBytes),
        _ => None,
    }
}
fn is_pointer_eq_type(ty: &Type) -> bool {
    matches!(
        semantic::resolve_struct_type(ty),
        Type::String | Type::Bytes | Type::Json
    ) || semantic::is_pointer_type(ty)
}
fn wide_numeric_kind_for_type(ty: &Type) -> Option<WideNumericKind> {
    match semantic::resolve_struct_type(ty) {
        Type::Int => Some(WideNumericKind::Int),
        Type::Decimal => Some(WideNumericKind::Decimal),
        Type::Quantity => Some(WideNumericKind::Quantity),
        _ => None,
    }
}
fn lower_map_key_eq(ctx: &mut LowerCtx, key_ty: &Type, left: Temp, right: Temp) -> Temp {
    if semantic::is_wide_numeric_type(key_ty) {
        let t = ctx.new_temp();
        ctx.current_instr(Instr::NumericCompare {
            dest: t,
            op: BinaryOp::Eq,
            left,
            right,
            kind: wide_numeric_kind_for_type(key_ty)
                .expect("wide numeric map key has a nominal ABI kind"),
        });
        t
    } else if is_pointer_eq_type(key_ty) {
        let t = ctx.new_temp();
        ctx.current_instr(Instr::PointerEq {
            dest: t,
            left,
            right,
        });
        t
    } else {
        let t = ctx.new_temp();
        ctx.current_instr(Instr::Binary {
            dest: t,
            op: BinaryOp::Eq,
            left,
            right,
        });
        t
    }
}
fn state_map_key_type(ty: &Type) -> Option<Type> {
    let ty = semantic::resolve_struct_type(ty);
    semantic::is_supported_durable_key_type(&ty).then_some(ty)
}
fn emit_state_value_schema_ref(ctx: &mut LowerCtx, ty: &Type) -> Option<Temp> {
    let schema = state_value_schema(ty)?;
    let encoded = ivm_abi::codec::encode_canonical_norito(&schema).ok()?;
    if encoded.len() > ivm_abi::state_value::MAX_STATE_VALUE_SCHEMA_BYTES {
        return None;
    }
    let schema_ref = emit_data_ref(
        ctx,
        DataRefKind::NoritoBytes,
        format!("0x{}", hex::encode(encoded)),
    );
    Some(schema_ref)
}
fn collect_state_value_words(
    ctx: &mut LowerCtx,
    value: Temp,
    ty: &Type,
    words: &mut Vec<Temp>,
) -> bool {
    match semantic::resolve_struct_type(ty) {
        Type::Struct { fields, .. } if fields.is_empty() => {
            words.push(emit_i64_const(ctx, 0));
            true
        }
        Type::Tuple(items) if items.is_empty() => {
            words.push(emit_i64_const(ctx, 0));
            true
        }
        Type::Struct { fields, .. } => fields.iter().enumerate().all(|(index, (_, field_ty))| {
            let field = emit_tuple_get(ctx, value, index);
            collect_state_value_words(ctx, field, field_ty, words)
        }),
        Type::Tuple(items) => items.iter().enumerate().all(|(index, item_ty)| {
            let item = emit_tuple_get(ctx, value, index);
            collect_state_value_words(ctx, item, item_ty, words)
        }),
        Type::Unit
        | Type::Enum(_)
        | Type::ErrorEnum(_)
        | Type::Option(_)
        | Type::Result(_, _)
        | Type::List(_, _)
        | Type::StateCursor(_) => {
            words.push(value);
            true
        }
        leaf => {
            if state_value_kind_for_type(&leaf).is_none() {
                return false;
            }
            words.push(value);
            true
        }
    }
}
fn collect_json_construction_words(
    ctx: &mut LowerCtx,
    expr: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
    words: &mut Vec<Temp>,
) -> bool {
    match expr.kind() {
        semantic::ExprKind::JsonObject(entries) => entries
            .iter()
            .all(|(_, value)| collect_json_construction_words(ctx, value, vars, words)),
        semantic::ExprKind::JsonArray(elements) => elements
            .iter()
            .all(|element| collect_json_construction_words(ctx, element, vars, words)),
        _ => {
            let value = lower_expr(ctx, expr, vars);
            collect_state_value_words(ctx, value, &expr.ty, words)
        }
    }
}
/// Materialize the same ordered scalar/aggregate-handle words used by public values.
fn materialize_value_word_table(ctx: &mut LowerCtx, words: &[Temp]) -> Temp {
    if words.is_empty() {
        return emit_i64_const(ctx, 0);
    }
    let Some(bytes) = words
        .len()
        .checked_mul(8)
        .and_then(|bytes| i64::try_from(bytes).ok())
    else {
        ctx.record_error("canonical value table exceeds the V1 byte limit".into());
        return emit_i64_const(ctx, 0);
    };
    let bytes = emit_i64_const(ctx, bytes);
    let table = emit_alloc(ctx, bytes);
    for (index, word) in words.iter().copied().enumerate() {
        let offset = index * 8;
        if let Ok(offset) = i16::try_from(offset) {
            emit_store64_imm(ctx, table, offset, word);
        } else {
            let offset = emit_i64_const(ctx, offset as i64);
            let address = emit_binary(ctx, BinaryOp::Add, table, offset);
            emit_store64_imm(ctx, address, 0, word);
        }
    }
    table
}
/// Capture source expressions once, then expose their declared parameter order.
fn lower_contract_call(
    ctx: &mut LowerCtx,
    method: &semantic::ContractMethod,
    args: &[TypedExpr],
    result: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let contract = lower_expr(ctx, &args[0], vars);
    let binding = ivm_abi::contract_call::ContractCallBindingV1 {
        code_hash: method.contract.code_hash,
        entrypoint: method.entrypoint,
    };
    let bytes = binding
        .to_bytes()
        .expect("validated canonical contract call binding");
    let binding = emit_data_ref(
        ctx,
        DataRefKind::NoritoBytes,
        format!("0x{}", hex::encode(bytes)),
    );
    let mut words = Vec::new();
    for argument in &args[1..] {
        let value = lower_expr(ctx, argument, vars);
        collect_function_value_words(ctx, value, &argument.ty, &mut words);
    }
    let argument_words = words.len();
    let payload = materialize_value_word_table(ctx, &words);
    let dests = if *result == Type::Unit {
        Vec::new()
    } else {
        runtime_value_word_types(result)
            .iter()
            .map(|_| ctx.new_temp())
            .collect::<Vec<_>>()
    };
    ctx.current_instr(Instr::CallContract {
        view: method.descriptor().kind
            == iroha_data_model::smart_contract::manifest::EntryPointKind::View,
        dests: dests.clone(),
        contract,
        binding,
        payload,
        argument_words,
    });
    if *result == Type::Unit {
        emit_i64_const(ctx, 0)
    } else {
        rebuild_runtime_value(ctx, result, &dests)
    }
}
fn lower_test_argument_record(
    ctx: &mut LowerCtx,
    expression: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> (Temp, usize) {
    let value = lower_expr(ctx, expression, vars);
    let mut words = Vec::new();
    match semantic::resolve_struct_type(&expression.ty) {
        Type::Struct { fields, .. } if fields.is_empty() => {}
        Type::Struct { .. } => collect_function_value_words(ctx, value, &expression.ty, &mut words),
        _ => ctx.record_error(
            "internal error: test arguments lack their contextual record type".into(),
        ),
    }
    let count = words.len();
    (materialize_value_word_table(ctx, &words), count)
}
fn lower_event_emission(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let [ordinal, payload] = args else {
        ctx.record_error(
            "internal error: event emission requires its ordinal and typed record".into(),
        );
        return emit_i64_const(ctx, 0);
    };
    let ordinal = lower_expr_as_u64(ctx, ordinal, vars);
    // Struct lowering captures each expression once in source order, then places
    // the resulting values in declared field order. Public output uses these words too.
    let value = lower_expr(ctx, payload, vars);
    let mut words = Vec::new();
    collect_function_value_words(ctx, value, &payload.ty, &mut words);
    let expected = entrypoint_value_type("event payload", &payload.ty)
        .ok()
        .and_then(|schema| schema.word_count());
    if expected != Some(words.len()) {
        ctx.record_error(
            "internal error: event payload differs from its canonical value schema".into(),
        );
        return emit_i64_const(ctx, 0);
    }
    let table = materialize_value_word_table(ctx, &words);
    let count = emit_i64_const(ctx, words.len() as i64);
    let result = ctx.new_temp();
    ctx.current_instr(Instr::DirectHelperSyscall {
        dest: result,
        syscall: ivm_abi::syscalls::SYSCALL_EMIT_CONTRACT_EVENT,
        args: vec![ordinal, table, count],
    });
    emit_i64_const(ctx, 0)
}
fn lower_json_construction(
    ctx: &mut LowerCtx,
    expr: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let construction = match json_construction_schema(expr) {
        Ok(construction) => construction,
        Err(error) => {
            ctx.record_error(format!("internal error: {error}"));
            return emit_i64_const(ctx, 0);
        }
    };
    let expected_words = construction.word_count;
    let encoded_schema = construction.encoded;
    let schema_ref = emit_data_ref(
        ctx,
        DataRefKind::NoritoBytes,
        format!("0x{}", hex::encode(encoded_schema)),
    );
    let mut words = Vec::with_capacity(expected_words);
    if !collect_json_construction_words(ctx, expr, vars, &mut words)
        || words.len() != expected_words
        || words.len() > ivm_abi::state_value::MAX_STATE_VALUE_WORDS
    {
        ctx.record_error("internal error: native JSON value-word schema mismatch".into());
        return emit_i64_const(ctx, 0);
    }
    let table = materialize_value_word_table(ctx, &words);
    let word_count = emit_i64_const(ctx, i64::try_from(expected_words).unwrap_or(i64::MAX));
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::DirectHelperSyscall {
        dest,
        syscall: ivm_abi::syscalls::SYSCALL_JSON_BUILD,
        args: vec![schema_ref, table, word_count],
    });
    dest
}
fn collect_function_value_words(ctx: &mut LowerCtx, value: Temp, ty: &Type, words: &mut Vec<Temp>) {
    match semantic::resolve_struct_type(ty) {
        Type::Struct { fields, .. } if fields.is_empty() => {
            words.push(emit_i64_const(ctx, 0));
        }
        Type::Tuple(items) if items.is_empty() => {
            words.push(emit_i64_const(ctx, 0));
        }
        Type::Struct { fields, .. } => {
            for (index, (_, field_ty)) in fields.iter().enumerate() {
                let field = emit_tuple_get(ctx, value, index);
                collect_function_value_words(ctx, field, field_ty, words);
            }
        }
        Type::Tuple(items) => {
            for (index, item_ty) in items.iter().enumerate() {
                let item = emit_tuple_get(ctx, value, index);
                collect_function_value_words(ctx, item, item_ty, words);
            }
        }
        Type::Option(_) | Type::Result(_, _) | Type::List(_, _) => words.push(value),
        _ => words.push(value),
    }
}
fn encode_aggregate_state_value(ctx: &mut LowerCtx, value: Temp, ty: &Type) -> Option<Temp> {
    let schema = emit_state_value_schema_ref(ctx, ty)?;
    let mut words = Vec::new();
    if !collect_state_value_words(ctx, value, ty, &mut words)
        || words.len() > ivm_abi::state_value::MAX_STATE_VALUE_WORDS
    {
        return None;
    }
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::StateValueEncode {
        dest,
        schema,
        words,
    });
    Some(dest)
}
fn load_state_value_word(ctx: &mut LowerCtx, table: Temp, index: &mut usize) -> Option<Temp> {
    let index_i16 = i16::try_from(*index).ok()?;
    let imm = ivm_abi::state_value::DECODED_STATE_VALUE_TABLE_OFFSET.checked_add(
        index_i16.checked_mul(ivm_abi::state_value::DECODED_STATE_VALUE_WORD_BYTES)?,
    )?;
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::Load64Imm {
        dest,
        base: table,
        imm,
    });
    *index = index.saturating_add(1);
    Some(dest)
}
fn rebuild_state_value_from_table(
    ctx: &mut LowerCtx,
    table: Temp,
    ty: &Type,
    index: &mut usize,
) -> Option<Temp> {
    match semantic::resolve_struct_type(ty) {
        Type::Struct { fields, .. } if fields.is_empty() => {
            load_state_value_word(ctx, table, index)?;
            Some(emit_tuple_pack(ctx, Vec::new()))
        }
        Type::Tuple(items) if items.is_empty() => {
            load_state_value_word(ctx, table, index)?;
            Some(emit_tuple_pack(ctx, Vec::new()))
        }
        Type::Struct { fields, .. } => {
            let items = fields
                .iter()
                .map(|(_, field_ty)| rebuild_state_value_from_table(ctx, table, field_ty, index))
                .collect::<Option<Vec<_>>>()?;
            let dest = emit_tuple_pack(ctx, items);
            Some(dest)
        }
        Type::Tuple(types) => {
            let items = types
                .iter()
                .map(|item_ty| rebuild_state_value_from_table(ctx, table, item_ty, index))
                .collect::<Option<Vec<_>>>()?;
            let dest = emit_tuple_pack(ctx, items);
            Some(dest)
        }
        Type::Unit
        | Type::Enum(_)
        | Type::ErrorEnum(_)
        | Type::Option(_)
        | Type::Result(_, _)
        | Type::List(_, _)
        | Type::StateCursor(_) => load_state_value_word(ctx, table, index),
        leaf => {
            state_value_kind_for_type(&leaf)?;
            load_state_value_word(ctx, table, index)
        }
    }
}
fn rebuild_function_value_from_words(
    ctx: &mut LowerCtx,
    ty: &Type,
    words: &[Temp],
    index: &mut usize,
) -> Option<Temp> {
    match semantic::resolve_struct_type(ty) {
        Type::Struct { fields, .. } if fields.is_empty() => {
            let _unit = *words.get(*index)?;
            *index = index.saturating_add(1);
            Some(emit_tuple_pack(ctx, Vec::new()))
        }
        Type::Tuple(items) if items.is_empty() => {
            let _unit = *words.get(*index)?;
            *index = index.saturating_add(1);
            Some(emit_tuple_pack(ctx, Vec::new()))
        }
        Type::Struct { fields, .. } => {
            let items = fields
                .iter()
                .map(|(_, field_ty)| rebuild_function_value_from_words(ctx, field_ty, words, index))
                .collect::<Option<Vec<_>>>()?;
            let dest = emit_tuple_pack(ctx, items);
            Some(dest)
        }
        Type::Tuple(types) => {
            let items = types
                .iter()
                .map(|item_ty| rebuild_function_value_from_words(ctx, item_ty, words, index))
                .collect::<Option<Vec<_>>>()?;
            let dest = emit_tuple_pack(ctx, items);
            Some(dest)
        }
        Type::Option(_) | Type::Result(_, _) | Type::List(_, _) => {
            let word = *words.get(*index)?;
            *index = index.saturating_add(1);
            Some(word)
        }
        _ => {
            let word = *words.get(*index)?;
            *index = index.saturating_add(1);
            Some(word)
        }
    }
}
fn list_layout_for_type(ty: &Type) -> Option<(Type, ivm_abi::list::ListLayoutV1)> {
    let Type::List(element, capacity) = semantic::resolve_struct_type(ty) else {
        return None;
    };
    let element_words = u64::try_from(runtime_value_word_types(&element).len()).ok()?;
    let layout = ivm_abi::list::ListLayoutV1::try_new(u64::from(capacity), element_words).ok()?;
    Some((*element, layout))
}
fn emit_i64_const(ctx: &mut LowerCtx, value: i64) -> Temp {
    let temp = ctx.new_temp();
    ctx.current_instr(Instr::Const { dest: temp, value });
    temp
}
fn emit_data_ref_into(ctx: &mut LowerCtx, dest: Temp, kind: DataRefKind, value: String) {
    ctx.current_instr(Instr::DataRef { dest, kind, value });
}

fn emit_data_ref(ctx: &mut LowerCtx, kind: DataRefKind, value: String) -> Temp {
    let dest = ctx.new_temp();
    emit_data_ref_into(ctx, dest, kind, value);
    dest
}

fn emit_copy(ctx: &mut LowerCtx, dest: Temp, src: Temp) {
    ctx.current_instr(Instr::Copy { dest, src });
}

fn emit_binary(ctx: &mut LowerCtx, op: BinaryOp, left: Temp, right: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::Binary {
        dest,
        op,
        left,
        right,
    });
    dest
}

fn emit_numeric_compare(
    ctx: &mut LowerCtx,
    op: BinaryOp,
    left: Temp,
    right: Temp,
    kind: WideNumericKind,
) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::NumericCompare {
        dest,
        op,
        left,
        right,
        kind,
    });
    dest
}

fn emit_pointer_eq(ctx: &mut LowerCtx, left: Temp, right: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::PointerEq { dest, left, right });
    dest
}

fn emit_unary(ctx: &mut LowerCtx, op: UnaryOp, operand: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::Unary { dest, op, operand });
    dest
}

fn emit_load64_imm(ctx: &mut LowerCtx, base: Temp, imm: i16) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::Load64Imm { dest, base, imm });
    dest
}

fn emit_store64_imm(ctx: &mut LowerCtx, base: Temp, imm: i16, value: Temp) {
    ctx.current_instr(Instr::Store64Imm { base, imm, value });
}

fn emit_tuple_get(ctx: &mut LowerCtx, tuple: Temp, index: usize) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::TupleGet { dest, tuple, index });
    dest
}

fn emit_tuple_pack(ctx: &mut LowerCtx, items: Vec<Temp>) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::TuplePack { dest, items });
    dest
}

fn emit_state_get(ctx: &mut LowerCtx, path: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::StateGet { dest, path });
    dest
}
fn emit_alloc(ctx: &mut LowerCtx, bytes: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::Alloc { dest, bytes });
    dest
}
fn emit_pointer_to_norito(ctx: &mut LowerCtx, value: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::PointerToNorito { dest, value });
    dest
}
fn emit_pointer_from_norito(ctx: &mut LowerCtx, blob: Temp, kind: DataRefKind) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::PointerFromNorito { dest, blob, kind });
    dest
}

/// Cross the internal scalar/source-value boundary explicitly.
///
/// Some internal arithmetic protocols return signed 64-bit words. A Kotodama
/// `int` is instead a nominal canonical 512-bit TLV value, so a raw word must
/// never escape from an intrinsic whose semantic result is `int`.
#[cfg(test)]
fn emit_int_from_i64(ctx: &mut LowerCtx, value: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::IntFromI64 { dest, value });
    dest
}
/// Materialize a non-negative machine word as a canonical source `int`.
fn emit_int_from_u64(ctx: &mut LowerCtx, value: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::IntFromU64 { dest, value });
    dest
}
fn emit_int_to_u64(ctx: &mut LowerCtx, value: Temp) -> Temp {
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::IntToU64 { dest, value });
    dest
}
fn emit_list_allocation(ctx: &mut LowerCtx, list_ty: &Type, initial_len: u64) -> Temp {
    let Some((_, layout)) = list_layout_for_type(list_ty) else {
        ctx.record_error("internal error: invalid List layout".into());
        return emit_i64_const(ctx, 0);
    };
    if initial_len > u64::from(layout.capacity()) {
        ctx.record_error("internal error: List initial length exceeds capacity".into());
    }
    let bytes = layout
        .allocation_bytes()
        .ok()
        .and_then(|bytes| i64::try_from(bytes).ok())
        .unwrap_or_else(|| {
            ctx.record_error("internal error: List allocation exceeds V1 limits".into());
            16
        });
    let bytes = emit_i64_const(ctx, bytes);
    let list = emit_alloc(ctx, bytes);
    let len = emit_i64_const(ctx, i64::try_from(initial_len).unwrap_or(i64::MAX));
    emit_store64_imm(ctx, list, 0, len);
    let capacity = emit_i64_const(ctx, i64::from(layout.capacity()));
    emit_store64_imm(ctx, list, 8, capacity);
    list
}
fn emit_list_slot_base(ctx: &mut LowerCtx, list: Temp, index: Temp, element_words: usize) -> Temp {
    let stride = element_words
        .checked_mul(8)
        .and_then(|stride| i64::try_from(stride).ok())
        .unwrap_or_else(|| {
            ctx.record_error("internal error: List element stride exceeds V1 limits".into());
            8
        });
    let stride = emit_i64_const(ctx, stride);
    let offset = emit_binary(ctx, BinaryOp::Mul, index, stride);
    emit_binary(ctx, BinaryOp::Add, list, offset)
}
fn emit_list_word_address(ctx: &mut LowerCtx, slot: Temp, word_index: usize) -> Temp {
    let offset = word_index
        .checked_add(2)
        .and_then(|word| word.checked_mul(8))
        .and_then(|offset| i64::try_from(offset).ok())
        .unwrap_or_else(|| {
            ctx.record_error("internal error: List word offset exceeds V1 limits".into());
            16
        });
    let offset = emit_i64_const(ctx, offset);
    emit_binary(ctx, BinaryOp::Add, slot, offset)
}
fn load_list_element(ctx: &mut LowerCtx, list: Temp, index: Temp, element_ty: &Type) -> Temp {
    let word_types = runtime_value_word_types(element_ty);
    let slot = emit_list_slot_base(ctx, list, index, word_types.len());
    let mut words = Vec::with_capacity(word_types.len());
    for word_index in 0..word_types.len() {
        let address = emit_list_word_address(ctx, slot, word_index);
        let word = ctx.new_temp();
        ctx.current_instr(Instr::Load64 {
            dest: word,
            address,
        });
        words.push(word);
    }
    let mut word_index = 0;
    let element = rebuild_function_value_from_words(ctx, element_ty, &words, &mut word_index)
        .unwrap_or_else(|| {
            ctx.record_error("internal error: cannot rebuild List element".into());
            list
        });
    if word_index != words.len() {
        ctx.record_error("internal error: List element word count mismatch".into());
    }
    element
}
fn store_list_element(
    ctx: &mut LowerCtx,
    list: Temp,
    index: Temp,
    element: Temp,
    element_ty: &Type,
) {
    let word_types = runtime_value_word_types(element_ty);
    let mut words = Vec::with_capacity(word_types.len());
    collect_function_value_words(ctx, element, element_ty, &mut words);
    if words.len() != word_types.len() {
        ctx.record_error("internal error: List element word count mismatch".into());
        return;
    }
    let slot = emit_list_slot_base(ctx, list, index, words.len());
    for (word_index, word) in words.into_iter().enumerate() {
        let address = emit_list_word_address(ctx, slot, word_index);
        ctx.current_instr(Instr::Store64 {
            address,
            value: word,
        });
    }
}
fn clear_list_element(ctx: &mut LowerCtx, list: Temp, index: Temp, element_ty: &Type) {
    let element_words = runtime_value_word_types(element_ty).len();
    let slot = emit_list_slot_base(ctx, list, index, element_words);
    let zero = emit_i64_const(ctx, 0);
    for word_index in 0..element_words {
        let address = emit_list_word_address(ctx, slot, word_index);
        ctx.current_instr(Instr::Store64 {
            address,
            value: zero,
        });
    }
}
fn emit_list_index_is_present(ctx: &mut LowerCtx, index: Temp, len: Temp) -> Temp {
    let zero = emit_data_ref(ctx, DataRefKind::Int, "0".to_owned());
    let len = emit_int_from_u64(ctx, len);
    let non_negative = emit_numeric_compare(ctx, BinaryOp::Ge, index, zero, WideNumericKind::Int);
    let below_len = emit_numeric_compare(ctx, BinaryOp::Lt, index, len, WideNumericKind::Int);
    emit_binary(ctx, BinaryOp::And, non_negative, below_len)
}
fn lower_list_literal(
    ctx: &mut LowerCtx,
    elements: &[TypedExpr],
    list_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let Some((element_ty, _)) = list_layout_for_type(list_ty) else {
        ctx.record_error("internal error: typed List literal lacks List type".into());
        return emit_i64_const(ctx, 0);
    };
    let list = emit_list_allocation(
        ctx,
        list_ty,
        u64::try_from(elements.len()).unwrap_or(u64::MAX),
    );
    for (index, element) in elements.iter().enumerate() {
        let value = lower_expr(ctx, element, vars);
        let index = emit_i64_const(ctx, i64::try_from(index).unwrap_or(i64::MAX));
        store_list_element(ctx, list, index, value, &element_ty);
    }
    list
}
fn lower_list_comprehension(
    ctx: &mut LowerCtx,
    expression: &TypedExpr,
    item: &str,
    source: &TypedExpr,
    condition: Option<&TypedExpr>,
    list_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let source_list = lower_expr(ctx, source, vars);
    let Type::List(source_element, _) = semantic::resolve_struct_type(&source.ty) else {
        ctx.record_error("internal error: List comprehension source lost its List type".into());
        return emit_i64_const(ctx, 0);
    };
    let Some((result_element, _)) = list_layout_for_type(list_ty) else {
        ctx.record_error("internal error: List comprehension result lost its List type".into());
        return emit_i64_const(ctx, 0);
    };
    let result = emit_list_allocation(ctx, list_ty, 0);
    let source_len = emit_load64_imm(ctx, source_list, 0);
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    let header = ctx.new_label();
    let body = ctx.new_label();
    let append = ctx.new_label();
    let step = ctx.new_label();
    let end = ctx.new_label();
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(header);
    let keep_going = emit_binary(ctx, BinaryOp::Lt, index, source_len);
    ctx.finish_current(Terminator::Branch {
        cond: keep_going,
        then_bb: body,
        else_bb: end,
    });
    ctx.start_block(body);
    let item_value = load_list_element(ctx, source_list, index, &source_element);
    let mut comprehension_vars = vars.clone();
    comprehension_vars.insert(item.to_owned(), item_value);
    if let Some(condition) = condition {
        let condition = lower_expr(ctx, condition, &mut comprehension_vars);
        ctx.finish_current(Terminator::Branch {
            cond: condition,
            then_bb: append,
            else_bb: step,
        });
    } else {
        ctx.finish_current(Terminator::Jump(append));
    }
    ctx.start_block(append);
    let value = lower_expr(ctx, expression, &mut comprehension_vars);
    let result_len = emit_load64_imm(ctx, result, 0);
    store_list_element(ctx, result, result_len, value, &result_element);
    ctx.current_instr(Instr::Binary {
        dest: result_len,
        op: BinaryOp::Add,
        left: result_len,
        right: one,
    });
    emit_store64_imm(ctx, result, 0, result_len);
    ctx.finish_current(Terminator::Jump(step));
    ctx.start_block(step);
    ctx.current_instr(Instr::Binary {
        dest: index,
        op: BinaryOp::Add,
        left: index,
        right: one,
    });
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(end);
    result
}
fn emit_product_value_eq(
    ctx: &mut LowerCtx,
    left: Temp,
    right: Temp,
    fields: impl IntoIterator<Item = Type>,
) -> Temp {
    let mut result = emit_i64_const(ctx, 1);
    for (index, field_ty) in fields.into_iter().enumerate() {
        let left_field = emit_tuple_get(ctx, left, index);
        let right_field = emit_tuple_get(ctx, right, index);
        let equal = emit_typed_value_eq(ctx, left_field, right_field, &field_ty);
        let combined = emit_binary(ctx, BinaryOp::And, result, equal);
        result = combined;
    }
    result
}
/// Compare two compiler-owned sums without observing their inactive payloads.
fn emit_sum_value_eq(ctx: &mut LowerCtx, left: Temp, right: Temp, ty: &Type) -> Temp {
    let left_tag = load_sum_tag(ctx, left);
    let right_tag = load_sum_tag(ctx, right);
    let tags_equal = emit_binary(ctx, BinaryOp::Eq, left_tag, right_tag);
    let matching_tags = ctx.new_label();
    let different_tags = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: tags_equal,
        then_bb: matching_tags,
        else_bb: different_tags,
    });
    ctx.start_block(different_tags);
    let false_value = emit_i64_const(ctx, 0);
    emit_copy(ctx, result, false_value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(matching_tags);
    match semantic::resolve_struct_type(ty) {
        Type::Option(payload) => {
            let some = ctx.new_label();
            let none = ctx.new_label();
            ctx.finish_current(Terminator::Branch {
                cond: left_tag,
                then_bb: some,
                else_bb: none,
            });
            ctx.start_block(none);
            let true_value = emit_i64_const(ctx, 1);
            emit_copy(ctx, result, true_value);
            ctx.finish_current(Terminator::Jump(end));
            ctx.start_block(some);
            let left_payload = load_sum_payload(ctx, left, &payload);
            let right_payload = load_sum_payload(ctx, right, &payload);
            let equal = emit_typed_value_eq(ctx, left_payload, right_payload, &payload);
            emit_copy(ctx, result, equal);
            ctx.finish_current(Terminator::Jump(end));
        }
        Type::Result(ok, err) => {
            let success = ctx.new_label();
            let failure = ctx.new_label();
            ctx.finish_current(Terminator::Branch {
                cond: left_tag,
                then_bb: success,
                else_bb: failure,
            });
            ctx.start_block(failure);
            let left_error = load_sum_payload(ctx, left, &err);
            let right_error = load_sum_payload(ctx, right, &err);
            let equal = emit_typed_value_eq(ctx, left_error, right_error, &err);
            emit_copy(ctx, result, equal);
            ctx.finish_current(Terminator::Jump(end));
            ctx.start_block(success);
            let left_value = load_sum_payload(ctx, left, &ok);
            let right_value = load_sum_payload(ctx, right, &ok);
            let equal = emit_typed_value_eq(ctx, left_value, right_value, &ok);
            emit_copy(ctx, result, equal);
            ctx.finish_current(Terminator::Jump(end));
        }
        _ => {
            ctx.record_error("internal error: aggregate equality expected Option or Result".into());
            let false_value = emit_i64_const(ctx, 0);
            emit_copy(ctx, result, false_value);
            ctx.finish_current(Terminator::Jump(end));
        }
    }
    ctx.start_block(end);
    result
}
/// Compare two bounded Lists by length and recursively by their active elements.
fn emit_list_value_eq(ctx: &mut LowerCtx, left: Temp, right: Temp, element_ty: &Type) -> Temp {
    let left_len = emit_load64_imm(ctx, left, 0);
    let right_len = emit_load64_imm(ctx, right, 0);
    let lengths_equal = emit_binary(ctx, BinaryOp::Eq, left_len, right_len);
    let compare_elements = ctx.new_label();
    let header = ctx.new_label();
    let body = ctx.new_label();
    let step = ctx.new_label();
    let different = ctx.new_label();
    let equal = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    ctx.finish_current(Terminator::Branch {
        cond: lengths_equal,
        then_bb: compare_elements,
        else_bb: different,
    });
    ctx.start_block(compare_elements);
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(header);
    let keep_going = emit_binary(ctx, BinaryOp::Lt, index, left_len);
    ctx.finish_current(Terminator::Branch {
        cond: keep_going,
        then_bb: body,
        else_bb: equal,
    });
    ctx.start_block(body);
    let left_element = load_list_element(ctx, left, index, element_ty);
    let right_element = load_list_element(ctx, right, index, element_ty);
    let elements_equal = emit_typed_value_eq(ctx, left_element, right_element, element_ty);
    ctx.finish_current(Terminator::Branch {
        cond: elements_equal,
        then_bb: step,
        else_bb: different,
    });
    ctx.start_block(step);
    ctx.current_instr(Instr::Binary {
        dest: index,
        op: BinaryOp::Add,
        left: index,
        right: one,
    });
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(different);
    let false_value = emit_i64_const(ctx, 0);
    emit_copy(ctx, result, false_value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(equal);
    let true_value = emit_i64_const(ctx, 1);
    emit_copy(ctx, result, true_value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    result
}
/// Branch on a local-test assertion; on failure, report the site, the compared values (encoded
/// as canonical state-value records with their schema), and the message to the test host.
///
/// The host-private syscall is emitted only in test projections, never in deployable artifacts.
/// A host that returns from it still stops at the trailing `Assert`.
fn emit_test_assertion(
    ctx: &mut LowerCtx,
    cond: Temp,
    site: &TypedExpr,
    values: Option<(Temp, Temp, &Type)>,
    message: Option<Temp>,
    vars: &mut HashMap<String, Temp>,
) {
    let failed = ctx.new_label();
    let passed = ctx.new_label();
    ctx.finish_current(Terminator::Branch {
        cond,
        then_bb: passed,
        else_bb: failed,
    });
    ctx.start_block(failed);
    let site = lower_expr(ctx, site, vars);
    let zero = emit_i64_const(ctx, 0);
    let (actual, expected, schema) = values
        .and_then(|(actual, expected, ty)| {
            let schema = emit_state_value_schema_ref(ctx, ty)?;
            let actual = encode_aggregate_state_value(ctx, actual, ty)?;
            let expected = encode_aggregate_state_value(ctx, expected, ty)?;
            Some((actual, expected, schema))
        })
        .unwrap_or((zero, zero, zero));
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::DirectHelperSyscall {
        dest,
        syscall: ivm_abi::syscalls::SYSCALL_KOTO_TEST_ASSERT_FAILED,
        args: vec![site, actual, expected, schema, message.unwrap_or(zero)],
    });
    ctx.current_instr(Instr::Assert { cond });
    ctx.finish_current(Terminator::Jump(passed));
    ctx.start_block(passed);
}
/// Hand the compiler-owned call-site record of the next `test::` helper call to the test host.
///
/// Emitted after the helper's operands are evaluated, so a helper call nested inside an operand
/// cannot overwrite the site. The host-private syscall exists only in test projections.
fn emit_test_call_site(
    ctx: &mut LowerCtx,
    site: Option<&TypedExpr>,
    vars: &mut HashMap<String, Temp>,
) {
    let Some(site) = site.filter(|site| matches!(site.kind(), semantic::ExprKind::Bytes(_))) else {
        return;
    };
    let site = lower_expr(ctx, site, vars);
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::DirectHelperSyscall {
        dest,
        syscall: ivm_abi::syscalls::SYSCALL_KOTO_TEST_CALL_SITE,
        args: vec![site],
    });
}
/// Emit canonical value equality shared by operators and List.contains.
fn emit_typed_value_eq(ctx: &mut LowerCtx, left: Temp, right: Temp, ty: &Type) -> Temp {
    match semantic::resolve_struct_type(ty) {
        Type::Struct { fields, .. } => emit_product_value_eq(
            ctx,
            left,
            right,
            fields.iter().map(|(_, field_ty)| field_ty.clone()),
        ),
        Type::Tuple(items) => emit_product_value_eq(ctx, left, right, items),
        Type::Option(_) | Type::Result(_, _) => emit_sum_value_eq(ctx, left, right, ty),
        Type::List(element, _) => emit_list_value_eq(ctx, left, right, &element),
        leaf => {
            if let Some(kind) = wide_numeric_kind_for_type(&leaf) {
                emit_numeric_compare(ctx, BinaryOp::Eq, left, right, kind)
            } else if is_pointer_eq_type(&leaf) {
                emit_pointer_eq(ctx, left, right)
            } else if matches!(
                leaf,
                Type::Unit | Type::Enum(_) | Type::ErrorEnum(_) | Type::Bool
            ) {
                emit_binary(ctx, BinaryOp::Eq, left, right)
            } else {
                ctx.record_error(format!(
                    "internal error: canonical equality cannot compare `{leaf:?}`"
                ));
                emit_i64_const(ctx, 0)
            }
        }
    }
}
fn lower_list_get(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let list = lower_expr(ctx, &args[0], vars);
    let index = lower_expr(ctx, &args[1], vars);
    let len = emit_load64_imm(ctx, list, 0);
    let present = emit_list_index_is_present(ctx, index, len);
    let some = ctx.new_label();
    let none = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: present,
        then_bb: some,
        else_bb: none,
    });
    ctx.start_block(some);
    let Type::Option(element_ty) = semantic::resolve_struct_type(result_ty) else {
        ctx.record_error("internal error: List.get result is not Option<T>".into());
        return emit_i64_const(ctx, 0);
    };
    // The dominating exact-int comparisons prove `0 <= index < len <= 64`,
    // so this scalar conversion cannot fail. Keeping it inside the active arm
    // makes arbitrary-width out-of-range indices return `Option::none`.
    let index = emit_int_to_u64(ctx, index);
    let value = load_list_element(ctx, list, index, &element_ty);
    let value = emit_sum_value(ctx, result_ty, 1, Some(value));
    emit_copy(ctx, result, value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(none);
    let value = emit_sum_value(ctx, result_ty, 0, None);
    emit_copy(ctx, result, value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    result
}
fn lower_list_try_set(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let list = lower_expr(ctx, &args[0], vars);
    let index = lower_expr(ctx, &args[1], vars);
    let value = lower_expr(ctx, &args[2], vars);
    let Type::List(element_ty, _) = semantic::resolve_struct_type(&args[0].ty) else {
        ctx.record_error("internal error: List.try_set receiver lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let len = emit_load64_imm(ctx, list, 0);
    let present = emit_list_index_is_present(ctx, index, len);
    let success = ctx.new_label();
    let failure = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: present,
        then_bb: success,
        else_bb: failure,
    });
    ctx.start_block(success);
    // Conversion is reached only after the exact-int bounds proof above.
    let index = emit_int_to_u64(ctx, index);
    store_list_element(ctx, list, index, value, &element_ty);
    let one = emit_i64_const(ctx, 1);
    emit_copy(ctx, result, one);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(failure);
    let zero = emit_i64_const(ctx, 0);
    emit_copy(ctx, result, zero);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    result
}
fn lower_list_mutation_result(
    ctx: &mut LowerCtx,
    success: Temp,
    error_code: i64,
    result_ty: &Type,
) -> Temp {
    let code = emit_i64_const(ctx, error_code);
    let unit = emit_i64_const(ctx, 0);
    if *result_ty == Type::Unit {
        let encoded =
            ivm_abi::codec::encode_canonical_norito(&ivm_abi::error_types::list_error_type())
                .expect("compiler-owned ListError schema encodes");
        let descriptor = emit_data_ref(
            ctx,
            DataRefKind::NoritoBytes,
            format!("0x{}", hex::encode(encoded)),
        );
        let cond = emit_unary(ctx, UnaryOp::Not, success);
        ctx.current_instr(Instr::AbortIf {
            cond,
            descriptor,
            code,
        });
        return unit;
    }
    let ok = ctx.new_label();
    let err = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: success,
        then_bb: ok,
        else_bb: err,
    });
    ctx.start_block(ok);
    let value = emit_sum_value(ctx, result_ty, 1, Some(unit));
    emit_copy(ctx, result, value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(err);
    let value = emit_sum_value(ctx, result_ty, 0, Some(code));
    emit_copy(ctx, result, value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    result
}
fn lower_list_try_push(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let list = lower_expr(ctx, &args[0], vars);
    let value = lower_expr(ctx, &args[1], vars);
    let Type::List(element_ty, capacity) = semantic::resolve_struct_type(&args[0].ty) else {
        ctx.record_error("internal error: List.try_push receiver lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let len = emit_load64_imm(ctx, list, 0);
    let capacity = emit_i64_const(ctx, i64::from(capacity));
    let has_capacity = emit_binary(ctx, BinaryOp::Lt, len, capacity);
    let success = ctx.new_label();
    let failure = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: has_capacity,
        then_bb: success,
        else_bb: failure,
    });
    ctx.start_block(success);
    store_list_element(ctx, list, len, value, &element_ty);
    let one = emit_i64_const(ctx, 1);
    let new_len = emit_binary(ctx, BinaryOp::Add, len, one);
    emit_store64_imm(ctx, list, 0, new_len);
    emit_copy(ctx, result, one);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(failure);
    let zero = emit_i64_const(ctx, 0);
    emit_copy(ctx, result, zero);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    result
}
fn lower_list_pop(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let list = lower_expr(ctx, &args[0], vars);
    let Type::Option(element_ty) = semantic::resolve_struct_type(result_ty) else {
        ctx.record_error("internal error: List.pop result is not Option<T>".into());
        return emit_i64_const(ctx, 0);
    };
    let len = emit_load64_imm(ctx, list, 0);
    let zero = emit_i64_const(ctx, 0);
    let non_empty = emit_binary(ctx, BinaryOp::Gt, len, zero);
    let some = ctx.new_label();
    let none = ctx.new_label();
    let end = ctx.new_label();
    let result = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: non_empty,
        then_bb: some,
        else_bb: none,
    });
    ctx.start_block(some);
    let one = emit_i64_const(ctx, 1);
    let new_len = emit_binary(ctx, BinaryOp::Sub, len, one);
    let value = load_list_element(ctx, list, new_len, &element_ty);
    clear_list_element(ctx, list, new_len, &element_ty);
    emit_store64_imm(ctx, list, 0, new_len);
    let value = emit_sum_value(ctx, result_ty, 1, Some(value));
    emit_copy(ctx, result, value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(none);
    let value = emit_sum_value(ctx, result_ty, 0, None);
    emit_copy(ctx, result, value);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    result
}
fn lower_list_contains(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let list = lower_expr(ctx, &args[0], vars);
    let needle = lower_expr(ctx, &args[1], vars);
    let Type::List(element_ty, _) = semantic::resolve_struct_type(&args[0].ty) else {
        ctx.record_error("internal error: List.contains receiver lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let len = emit_load64_imm(ctx, list, 0);
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    let result = emit_i64_const(ctx, 0);
    let header = ctx.new_label();
    let body = ctx.new_label();
    let found = ctx.new_label();
    let step = ctx.new_label();
    let end = ctx.new_label();
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(header);
    let keep_going = emit_binary(ctx, BinaryOp::Lt, index, len);
    ctx.finish_current(Terminator::Branch {
        cond: keep_going,
        then_bb: body,
        else_bb: end,
    });
    ctx.start_block(body);
    let candidate = load_list_element(ctx, list, index, &element_ty);
    let equal = emit_typed_value_eq(ctx, candidate, needle, &element_ty);
    ctx.finish_current(Terminator::Branch {
        cond: equal,
        then_bb: found,
        else_bb: step,
    });
    ctx.start_block(found);
    emit_copy(ctx, result, one);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(step);
    ctx.current_instr(Instr::Binary {
        dest: index,
        op: BinaryOp::Add,
        left: index,
        right: one,
    });
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(end);
    result
}
fn lower_list_take(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let source = lower_expr(ctx, &args[0], vars);
    let limit = if let Some(limit) = args.get(1) {
        lower_expr_as_u64(ctx, limit, vars)
    } else {
        let Type::List(_, capacity) = semantic::resolve_struct_type(result_ty) else {
            ctx.record_error("internal error: widening result is not a List".into());
            return emit_i64_const(ctx, 0);
        };
        emit_i64_const(ctx, i64::from(capacity))
    };
    let Type::List(source_element, _) = semantic::resolve_struct_type(&args[0].ty) else {
        ctx.record_error("internal error: List.take receiver lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let Some((result_element, _)) = list_layout_for_type(result_ty) else {
        ctx.record_error("internal error: List.take result lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let result = emit_list_allocation(ctx, result_ty, 0);
    let source_len = emit_load64_imm(ctx, source, 0);
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    let header = ctx.new_label();
    let body = ctx.new_label();
    let end = ctx.new_label();
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(header);
    let below_len = emit_binary(ctx, BinaryOp::Lt, index, source_len);
    let below_limit = emit_binary(ctx, BinaryOp::Lt, index, limit);
    let keep_going = emit_binary(ctx, BinaryOp::And, below_len, below_limit);
    ctx.finish_current(Terminator::Branch {
        cond: keep_going,
        then_bb: body,
        else_bb: end,
    });
    ctx.start_block(body);
    let value = load_list_element(ctx, source, index, &source_element);
    store_list_element(ctx, result, index, value, &result_element);
    let new_len = emit_binary(ctx, BinaryOp::Add, index, one);
    emit_store64_imm(ctx, result, 0, new_len);
    emit_copy(ctx, index, new_len);
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(end);
    result
}
fn lower_list_enumerate(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let source = lower_expr(ctx, &args[0], vars);
    let Type::List(source_element, _) = semantic::resolve_struct_type(&args[0].ty) else {
        ctx.record_error("internal error: List.enumerate receiver lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let Some((result_element, _)) = list_layout_for_type(result_ty) else {
        ctx.record_error("internal error: List.enumerate result lost List type".into());
        return emit_i64_const(ctx, 0);
    };
    let result = emit_list_allocation(ctx, result_ty, 0);
    let source_len = emit_load64_imm(ctx, source, 0);
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    let header = ctx.new_label();
    let body = ctx.new_label();
    let end = ctx.new_label();
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(header);
    let keep_going = emit_binary(ctx, BinaryOp::Lt, index, source_len);
    ctx.finish_current(Terminator::Branch {
        cond: keep_going,
        then_bb: body,
        else_bb: end,
    });
    ctx.start_block(body);
    let value = load_list_element(ctx, source, index, &source_element);
    let source_index = emit_int_from_u64(ctx, index);
    let pair = emit_tuple_pack(ctx, vec![source_index, value]);
    store_list_element(ctx, result, index, pair, &result_element);
    let new_len = emit_binary(ctx, BinaryOp::Add, index, one);
    emit_store64_imm(ctx, result, 0, new_len);
    emit_copy(ctx, index, new_len);
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(end);
    result
}
fn lower_list_intrinsic(
    ctx: &mut LowerCtx,
    name: CompilerIntrinsic,
    args: &[TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Option<Temp> {
    Some(match name {
        CompilerIntrinsic::ListLen => {
            let list = lower_expr(ctx, &args[0], vars);
            let len = emit_load64_imm(ctx, list, 0);
            emit_int_from_u64(ctx, len)
        }
        CompilerIntrinsic::ListGet => lower_list_get(ctx, args, result_ty, vars),
        CompilerIntrinsic::ListSet | CompilerIntrinsic::ListTrySet => {
            let success = lower_list_try_set(ctx, args, vars);
            lower_list_mutation_result(ctx, success, 1, result_ty)
        }
        CompilerIntrinsic::ListPush | CompilerIntrinsic::ListTryPush => {
            let success = lower_list_try_push(ctx, args, vars);
            lower_list_mutation_result(ctx, success, 2, result_ty)
        }
        CompilerIntrinsic::ListPop => lower_list_pop(ctx, args, result_ty, vars),
        CompilerIntrinsic::ListContains => lower_list_contains(ctx, args, vars),
        CompilerIntrinsic::ListTake | CompilerIntrinsic::ListWiden => {
            lower_list_take(ctx, args, result_ty, vars)
        }
        CompilerIntrinsic::ListEnumerate => lower_list_enumerate(ctx, args, result_ty, vars),
        _ => return None,
    })
}
fn lower_numeric_round_intrinsic(
    ctx: &mut LowerCtx,
    name: CompilerIntrinsic,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Option<Temp> {
    let (op, result_kind) = match name {
        CompilerIntrinsic::DecimalMulDivRound => {
            (NumericRoundOp::DecimalMulDiv, WideNumericKind::Decimal)
        }
        CompilerIntrinsic::QuantityMulDivRound => {
            (NumericRoundOp::QuantityMulDiv, WideNumericKind::Quantity)
        }
        CompilerIntrinsic::DecimalDivRound => {
            (NumericRoundOp::DecimalDiv, WideNumericKind::Decimal)
        }
        CompilerIntrinsic::QuantityDivRound => {
            (NumericRoundOp::QuantityDiv, WideNumericKind::Quantity)
        }
        CompilerIntrinsic::QuantityRatioRound => {
            (NumericRoundOp::QuantityRatio, WideNumericKind::Decimal)
        }
        _ => return None,
    };
    let fused = matches!(
        op,
        NumericRoundOp::DecimalMulDiv | NumericRoundOp::QuantityMulDiv
    );
    if args.len() != if fused { 5 } else { 4 } {
        ctx.record_error(
            "internal error: rounded numeric division requires dividend, divisor, scale, and mode"
                .into(),
        );
        return Some(emit_i64_const(ctx, 0));
    }
    let dividend = lower_expr(ctx, &args[0], vars);
    let multiplier = fused.then(|| lower_expr(ctx, &args[1], vars));
    let offset = usize::from(fused);
    let divisor = lower_expr(ctx, &args[1 + offset], vars);
    let scale = lower_expr(ctx, &args[2 + offset], vars);
    let mode = lower_expr_as_u64(ctx, &args[3 + offset], vars);
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::NumericRound {
        dest,
        dividend,
        multiplier,
        divisor,
        scale,
        mode,
        op,
        result_kind,
    });
    Some(dest)
}
fn lower_decimal_to_int_intrinsic(
    ctx: &mut LowerCtx,
    name: CompilerIntrinsic,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Option<Temp> {
    let (op, expected_args) = match name {
        CompilerIntrinsic::DecimalToIntTrunc => (DecimalToIntOp::Truncate, 1),
        CompilerIntrinsic::DecimalToIntRound => (DecimalToIntOp::Round, 2),
        _ => return None,
    };
    if args.len() != expected_args {
        ctx.record_error("internal error: malformed decimal-to-int intrinsic".into());
        return Some(emit_i64_const(ctx, 0));
    }
    let value = lower_expr(ctx, &args[0], vars);
    let mode = args.get(1).map(|mode| lower_expr_as_u64(ctx, mode, vars));
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::DecimalToInt {
        dest,
        value,
        mode,
        op,
    });
    Some(dest)
}
fn sum_pattern_tag(pattern: &semantic::TypedSumPattern) -> u64 {
    match &pattern.pattern.variant {
        SumVariant::OptionNone | SumVariant::ResultErr => 0,
        SumVariant::OptionSome | SumVariant::ResultOk => 1,
        SumVariant::Nominal { .. } => {
            u64::from(pattern.variant_code.expect("resolved nominal variant"))
        }
    }
}
fn pattern_matches(ctx: &mut LowerCtx, pattern: &semantic::TypedSumPattern, value: Temp) -> Temp {
    let observed = if pattern.variant_code.is_some() {
        value
    } else {
        load_sum_tag(ctx, value)
    };
    let expected = emit_i64_const(ctx, sum_pattern_tag(pattern) as i64);
    emit_binary(ctx, BinaryOp::Eq, observed, expected)
}
fn branch_on_sum_pattern(
    ctx: &mut LowerCtx,
    pattern: &semantic::TypedSumPattern,
    value: Temp,
    matched: Label,
    unmatched: Label,
) {
    let (cond, then_bb, else_bb) = match &pattern.pattern.variant {
        // Option and Result use canonical zero/one tags. Branch on the tag
        // directly, as exhaustive match does, without adding a comparison.
        SumVariant::OptionSome | SumVariant::ResultOk => {
            (load_sum_tag(ctx, value), matched, unmatched)
        }
        SumVariant::OptionNone | SumVariant::ResultErr => {
            (load_sum_tag(ctx, value), unmatched, matched)
        }
        // Nominal enum variants have explicit nonzero codes, not boolean tags.
        SumVariant::Nominal { .. } => (pattern_matches(ctx, pattern, value), matched, unmatched),
    };
    ctx.finish_current(Terminator::Branch {
        cond,
        then_bb,
        else_bb,
    });
}
fn bind_sum_pattern(
    ctx: &mut LowerCtx,
    pattern: &semantic::TypedSumPattern,
    value: Temp,
    vars: &mut HashMap<String, Temp>,
) {
    let Some(payload_ty) = &pattern.payload_type else {
        return;
    };
    let Some(binding) = &pattern.pattern.binding else {
        return;
    };
    if let PatternBinding::Name(name) = binding {
        let payload = load_sum_payload(ctx, value, payload_ty);
        vars.insert(name.clone(), payload);
    }
}
fn propagation_match_return<'a>(
    value_ty: &Type,
    return_ty: &Type,
    arms: &'a [semantic::TypedMatchArm],
) -> Option<(&'a semantic::TypedMatchArm, &'a semantic::TypedMatchArm)> {
    if arms.len() != 2 || matches!(value_ty, Type::Enum(_) | Type::ErrorEnum(_)) {
        return None;
    }
    let success = arms.iter().find(|arm| sum_pattern_tag(&arm.pattern) == 1)?;
    let failure = arms.iter().find(|arm| sum_pattern_tag(&arm.pattern) == 0)?;
    let success_binding = match success.pattern.pattern.binding.as_ref()? {
        PatternBinding::Name(name) => name,
        PatternBinding::Wildcard => return None,
    };
    if !success.body.statements.is_empty()
        || !matches!(
            success.body.tail.as_deref(),
            Some(TypedExpr {
                expr: semantic::ExprKind::Ident(name),
                ..
            }) if name == success_binding
        )
    {
        return None;
    }
    let [TypedStatement::Return(Some(returned))] = failure.body.statements.as_slice() else {
        return None;
    };
    if failure.body.tail.is_some()
        || semantic::resolve_struct_type(&returned.ty) != semantic::resolve_struct_type(return_ty)
    {
        return None;
    }
    match (
        semantic::resolve_struct_type(value_ty),
        semantic::resolve_struct_type(return_ty),
    ) {
        (Type::Option(_), Type::Option(_)) => (failure.pattern.pattern.variant
            == SumVariant::OptionNone
            && failure.pattern.pattern.binding.is_none()
            && matches!(&returned.expr, semantic::ExprKind::OptionNone))
        .then_some((success, failure)),
        (Type::Result(_, source_error), Type::Result(_, target_error))
            if source_error == target_error =>
        {
            let failure_binding = match failure.pattern.pattern.binding.as_ref()? {
                PatternBinding::Name(name) => name,
                PatternBinding::Wildcard => return None,
            };
            match &returned.expr {
                semantic::ExprKind::ResultErr { error }
                    if matches!(
                        error.as_ref(),
                        TypedExpr {
                            expr: semantic::ExprKind::Ident(name),
                            ..
                        } if name == failure_binding
                    ) =>
                {
                    Some((success, failure))
                }
                _ => None,
            }
        }
        _ => None,
    }
}
fn lower_propagation(
    ctx: &mut LowerCtx,
    value: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let sum = lower_expr(ctx, value, vars);
    let tag = load_sum_tag(ctx, sum);
    let success_label = ctx.new_label();
    let failure_label = ctx.new_label();
    ctx.finish_current(Terminator::Branch {
        cond: tag,
        then_bb: success_label,
        else_bb: failure_label,
    });
    ctx.start_block(failure_label);
    let return_ty = ctx.function_return_type.clone();
    let propagated = match (
        sum_layout_for_type(&value.ty),
        sum_layout_for_type(&return_ty),
    ) {
        // A failed sum has no active success payload. Reusing its canonical
        // handle is sound when the complete source and destination allocations
        // have the same shape.
        (Some(source), Some(target)) if source == target => sum,
        (Some(_), Some(_)) => match (
            semantic::resolve_struct_type(&value.ty),
            semantic::resolve_struct_type(&return_ty),
        ) {
            (Type::Option(_), Type::Option(_)) => emit_sum_value(ctx, &return_ty, 0, None),
            (Type::Result(_, source_error), Type::Result(_, _)) => {
                // Semantic analysis requires the exact same error type, with
                // no implicit conversion. Only that active payload is read and
                // copied into the destination layout; the differently-sized
                // inactive success branch remains canonical zero.
                let error = load_sum_payload(ctx, sum, &source_error);
                emit_sum_value(ctx, &return_ty, 0, Some(error))
            }
            _ => {
                ctx.record_error("internal error: propagation changed Option/Result family".into());
                sum
            }
        },
        _ => {
            ctx.record_error("internal error: invalid propagation return layout".into());
            sum
        }
    };
    finish_value_return(ctx, propagated, &return_ty);
    ctx.start_block(success_label);
    let payload_ty = match semantic::resolve_struct_type(&value.ty) {
        Type::Option(payload) | Type::Result(payload, _) => *payload,
        _ => {
            ctx.record_error("internal error: propagation operand is not a sum".into());
            Type::Unit
        }
    };
    load_sum_payload(ctx, sum, &payload_ty)
}
fn copy_runtime_value_words(ctx: &mut LowerCtx, value: Temp, ty: &Type, destinations: &[Temp]) {
    let mut words = Vec::with_capacity(destinations.len());
    collect_function_value_words(ctx, value, ty, &mut words);
    if words.len() != destinations.len() {
        ctx.record_error("internal error: branch result word count mismatch".into());
    }
    for (dest, src) in destinations.iter().zip(words) {
        ctx.current_instr(Instr::Copy { dest: *dest, src });
    }
}
fn rebuild_runtime_value(ctx: &mut LowerCtx, ty: &Type, words: &[Temp]) -> Temp {
    let mut index = 0;
    let value =
        rebuild_function_value_from_words(ctx, ty, words, &mut index).unwrap_or_else(|| {
            ctx.record_error("internal error: cannot rebuild branch result".into());
            words
                .first()
                .copied()
                .unwrap_or_else(|| emit_i64_const(ctx, 0))
        });
    if index != words.len() {
        ctx.record_error("internal error: branch result ABI width mismatch".into());
    }
    value
}
fn decode_aggregate_state_value(ctx: &mut LowerCtx, blob: Temp, ty: &Type) -> Option<Temp> {
    let schema = emit_state_value_schema_ref(ctx, ty)?;
    let table = ctx.new_temp();
    ctx.current_instr(Instr::DirectHelperSyscall {
        dest: table,
        syscall: ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE,
        args: vec![schema, blob],
    });
    let mut index = 0;
    let value = rebuild_state_value_from_table(ctx, table, ty, &mut index)?;
    let expected = state_value_schema(ty)?.word_kinds()?.len();
    (index == expected).then_some(value)
}
fn is_canonical_state_value_type(ty: &Type) -> bool {
    state_value_schema(ty).is_some()
}
fn lower_state_map_get_value(
    ctx: &mut LowerCtx,
    base_name: &str,
    key_tmp: Temp,
    key_ty: &Type,
    value_ty: &Type,
) -> Option<Temp> {
    let key_type = state_map_key_type(key_ty)?;
    let path = build_state_map_path(ctx, base_name, key_tmp, &key_type);
    let blob = ctx.new_temp();
    ctx.current_instr(Instr::StateGet { dest: blob, path });
    decode_state_map_value_blob(ctx, blob, value_ty)
}
fn decode_state_map_value_blob(ctx: &mut LowerCtx, blob: Temp, value_ty: &Type) -> Option<Temp> {
    let resolved = semantic::resolve_struct_type(value_ty);
    if !is_canonical_state_value_type(&resolved) {
        return None;
    }
    decode_aggregate_state_value(ctx, blob, &resolved)
}
fn lower_state_map_set_value(
    ctx: &mut LowerCtx,
    base_name: &str,
    key_tmp: Temp,
    key_ty: &Type,
    value_ty: &Type,
    value_tmp: Temp,
) -> bool {
    let resolved = semantic::resolve_struct_type(value_ty);
    let Some(key_type) = state_map_key_type(key_ty) else {
        return false;
    };
    let path = build_state_map_path(ctx, base_name, key_tmp, &key_type);
    if !is_canonical_state_value_type(&resolved) {
        return false;
    }
    let Some(encoded) = encode_aggregate_state_value(ctx, value_tmp, &resolved) else {
        return false;
    };
    ctx.current_instr(Instr::StateSet {
        path,
        value: encoded,
    });
    true
}
/// Control-flow terminators for a block.
#[derive(Debug, PartialEq)]
pub enum Terminator {
    Return(Option<Temp>),
    /// Return two flattened words through the caller-owned result table.
    Return2(Temp, Temp),
    /// Return N flattened words through the caller-owned result table in order.
    ReturnN(Vec<Temp>),
    Jump(Label),
    Branch {
        cond: Temp,
        then_bb: Label,
        else_bb: Label,
    },
}
/// Lower a semantically checked program into IR.
pub fn lower(program: &TypedProgram) -> Result<Program, String> {
    lower_with_cap(
        program,
        crate::semantic::COLLECTION_ITERATION_LIMIT as usize,
    )
}
/// Lower with the first-release dynamic-iteration cap.
pub fn lower_with_cap(program: &TypedProgram, dyn_iter_cap: usize) -> Result<Program, String> {
    crate::session::run_with_compiler_stack(move || {
        lower_with_cap_diagnostics(program, dyn_iter_cap).map_err(|failures| {
            failures
                .into_iter()
                .map(|failure| failure.message)
                .collect::<Vec<_>>()
                .join("\n")
        })
    })
    .unwrap_or_else(|_| {
        Err("compiler could not allocate the bounded stack required to lower source nesting".into())
    })
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LoweringFailure {
    pub(crate) message: String,
    pub(crate) location: super::ast::SourceLocation,
}
pub(crate) fn lower_with_cap_diagnostics(
    program: &TypedProgram,
    dyn_iter_cap: usize,
) -> Result<Program, Vec<LoweringFailure>> {
    let call_renames = HashMap::new();
    let function_param_specs = build_function_param_specs(program);
    let mut functions = Vec::new();
    let mut failures = Vec::new();
    for item in &program.items {
        let TypedItem::Function(function) = item;
        match lower_function_named(
            function,
            &function.name,
            &program.states,
            dyn_iter_cap,
            &call_renames,
            &function_param_specs,
        ) {
            Ok(function) => functions.push(function),
            Err(message) => failures.push(LoweringFailure {
                message,
                location: function.location,
            }),
        }
    }
    if failures.is_empty() {
        Ok(Program { functions })
    } else {
        Err(failures)
    }
}
fn build_function_param_specs(program: &TypedProgram) -> HashMap<String, Vec<TypedParam>> {
    let mut specs = HashMap::new();
    for item in &program.items {
        let TypedItem::Function(func) = item;
        specs.insert(func.name.clone(), func.param_types.clone());
    }
    specs
}
fn lower_function_named(
    func: &TypedFunction,
    symbol_name: &str,
    states: &[TypedStateDecl],
    dyn_iter_cap: usize,
    call_renames: &HashMap<String, String>,
    function_param_specs: &HashMap<String, Vec<TypedParam>>,
) -> Result<Function, String> {
    let mut ctx = LowerCtx::new(
        func.ret_ty.clone().unwrap_or(Type::Unit),
        dyn_iter_cap,
        call_renames.clone(),
        function_param_specs.clone(),
    );
    let entry = ctx.new_label();
    ctx.start_block(entry);
    // Ephemeral state allocation for seiyaku-level `state` declarations.
    let mut vars = HashMap::new();
    let mut param_temps = Vec::new();
    let lowered_params = lowered_function_params(&func.param_types);
    if lowered_params.len() > crate::regalloc::MAX_ARGUMENT_VALUES {
        return Err(format!(
            "function `{}` requires {} flattened argument words, exceeding the Kotodama V1 limit of {}",
            func.name,
            lowered_params.len(),
            crate::regalloc::MAX_ARGUMENT_VALUES,
        ));
    }
    for param in &lowered_params {
        let tmp = ctx.new_temp();
        param_temps.push((param.clone(), tmp));
        ctx.current_instr(Instr::LoadVar {
            dest: tmp,
            name: param.clone(),
        });
    }
    let mut state_entries = states.iter().collect::<Vec<_>>();
    state_entries.sort_by(|left, right| left.name.cmp(&right.name));
    for state in state_entries {
        register_state_value_metadata(&mut ctx, &state.name, &state.ty, &state.name);
    }
    let loaded_params = param_temps.into_iter().collect::<HashMap<_, _>>();
    for param in &func.param_types {
        ctx.binding_types
            .insert(param.name.clone(), param.ty.clone());
        if param.is_state {
            let tmp = *loaded_params.get(&param.name).ok_or_else(|| {
                format!(
                    "internal error: missing lowered state parameter `{}`",
                    param.name
                )
            })?;
            ctx.state_runtime_roots.insert(param.name.clone(), tmp);
            if let Type::StateMap(key, value) = semantic::resolve_struct_type(&param.ty) {
                ctx.state_map_configs.insert(
                    param.name.clone(),
                    StateMapSpec {
                        key: *key,
                        value: *value,
                    },
                );
            }
        } else if let Some(word_types) = function_value_word_types(&param.ty) {
            let words = (0..word_types.len())
                .map(|index| {
                    loaded_params
                        .get(&function_param_word_name(&param.name, index))
                        .copied()
                        .ok_or_else(|| {
                            format!(
                                "internal error: missing ABI word {index} for parameter `{}`",
                                param.name
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut index = 0;
            let value = rebuild_function_value_from_words(&mut ctx, &param.ty, &words, &mut index)
                .ok_or_else(|| {
                    format!(
                        "internal error: cannot rebuild aggregate parameter `{}`",
                        param.name
                    )
                })?;
            if index != words.len() {
                return Err(format!(
                    "internal error: aggregate parameter `{}` ABI word count mismatch",
                    param.name
                ));
            }
            vars.insert(param.name.clone(), value);
        } else {
            let tmp = *loaded_params.get(&param.name).ok_or_else(|| {
                format!("internal error: missing lowered parameter `{}`", param.name)
            })?;
            vars.insert(param.name.clone(), tmp);
        }
    }
    let tail = lower_block_tail_with_live_after(&mut ctx, &func.body, &mut vars, &BTreeSet::new());
    if semantic::typed_block_diverges(&func.body) {
        // Explicit returns already terminate every reachable path. Seal the
        // compiler-only continuation created so lowering can keep walking
        // unreachable source. SSA validates and budgets the full lowering IR
        // before removing this dead self-loop.
        seal_unreachable_continuation(&mut ctx);
    } else if let Some(value) = tail {
        let tail_ty = func
            .body
            .tail
            .as_ref()
            .map(|tail| tail.ty.clone())
            .unwrap_or(Type::Unit);
        finish_value_return(&mut ctx, value, &tail_ty);
    } else {
        let unit = emit_i64_const(&mut ctx, 0);
        ctx.finish_current(Terminator::Return(Some(unit)));
    }
    let function = Function {
        name: symbol_name.to_string(),
        params: lowered_params,
        blocks: ctx.blocks,
        entry,
        location: func.location,
    };
    if let Some(err) = ctx.error {
        Err(err)
    } else {
        Ok(function)
    }
}
fn lower_blob_literal(ctx: &mut LowerCtx, value: &str) -> Temp {
    emit_data_ref(ctx, DataRefKind::Blob, value.to_owned())
}
fn entrypoint_value_kind(
    value_name: &str,
    ty: &Type,
) -> Result<ivm_abi::entrypoint::EntrypointValueKindV1, String> {
    crate::abi_schema::public_value_kind(&semantic::resolve_struct_type(ty)).ok_or_else(|| {
        format!("entrypoint value `{value_name}` uses unsupported public type {ty:?}")
    })
}
fn append_entrypoint_value_type_nodes(
    value_name: &str,
    ty: &Type,
    nodes: &mut Vec<ivm_abi::entrypoint::EntrypointValueTypeNodeV1>,
) -> Result<(), String> {
    use ivm_abi::entrypoint::{
        EntrypointListTypeNodeV1 as ListNode, EntrypointStructTypeNodeV1 as StructNode,
        EntrypointValueTypeNodeV1 as Node,
    };
    match semantic::resolve_struct_type(ty) {
        Type::Unit => nodes.push(Node::Unit),
        Type::Enum(descriptor) => nodes.push(Node::Enum((*descriptor).clone())),
        Type::ErrorEnum(descriptor) => nodes.push(Node::Error((*descriptor).clone())),
        Type::StateCursor(key) => nodes.push(Node::StateCursor(
            crate::abi_schema::state_map_key_schema(&key)
                .ok_or_else(|| format!("{value_name}: invalid StateCursor key schema"))?,
        )),
        Type::Struct { name, fields } => {
            nodes.push(Node::Struct(StructNode {
                name,
                fields: fields.iter().map(|(name, _)| name.clone()).collect(),
            }));
            for (_, field_ty) in fields.iter() {
                append_entrypoint_value_type_nodes(value_name, field_ty, nodes)?;
            }
        }
        Type::Tuple(items) => {
            let arity = u16::try_from(items.len())
                .map_err(|_| format!("entrypoint value `{value_name}` tuple arity exceeds u16"))?;
            nodes.push(Node::Tuple(arity));
            for item in items {
                append_entrypoint_value_type_nodes(value_name, &item, nodes)?;
            }
        }
        Type::Option(inner) => {
            nodes.push(Node::Option);
            append_entrypoint_value_type_nodes(value_name, &inner, nodes)?;
        }
        Type::Result(ok, err) => {
            nodes.push(Node::Result);
            append_entrypoint_value_type_nodes(value_name, &ok, nodes)?;
            append_entrypoint_value_type_nodes(value_name, &err, nodes)?;
        }
        Type::List(element, capacity) => {
            nodes.push(Node::List(ListNode { capacity }));
            append_entrypoint_value_type_nodes(value_name, &element, nodes)?;
        }
        leaf => nodes.push(Node::Leaf(entrypoint_value_kind(value_name, &leaf)?)),
    }
    Ok(())
}
fn entrypoint_value_type(
    value_name: &str,
    ty: &Type,
) -> Result<ivm_abi::entrypoint::EntrypointValueTypeV1, String> {
    let mut nodes = Vec::new();
    append_entrypoint_value_type_nodes(value_name, ty, &mut nodes)?;
    let ty = ivm_abi::entrypoint::EntrypointValueTypeV1 { nodes };
    if !ty.validate() {
        return Err(format!(
            "entrypoint value `{value_name}` exceeds ABI v1 type depth, node, or word limits"
        ));
    }
    Ok(ty)
}
/// Build the exact recursive schema for every public return value, including Unit.
pub(crate) fn entrypoint_return_schema(
    entrypoint_name: &str,
    ty: Option<&Type>,
) -> Result<Option<ivm_abi::entrypoint::EntrypointValueTypeV1>, String> {
    let ty = ty.unwrap_or(&Type::Unit);
    let schema = entrypoint_value_type(entrypoint_name, ty)?;
    let words = schema
        .word_count()
        .ok_or_else(|| format!("entrypoint `{entrypoint_name}` has an invalid return schema"))?;
    if words > ivm_abi::entrypoint::MAX_ENTRYPOINT_RETURN_WORDS {
        return Err(format!(
            "entrypoint `{entrypoint_name}` returns {words} flattened words, exceeding the ABI v1 public table limit of {}",
            ivm_abi::entrypoint::MAX_ENTRYPOINT_RETURN_WORDS,
        ));
    }
    Ok(Some(schema))
}
pub(crate) fn entrypoint_argument_schema(
    params: &[TypedParam],
) -> Result<Option<ivm_abi::entrypoint::EntrypointArgumentSchemaV1>, String> {
    if params.is_empty() {
        return Ok(None);
    }
    let fields = params
        .iter()
        .map(|param| {
            Ok(ivm_abi::entrypoint::EntrypointArgumentFieldV1 {
                name: param.name.clone(),
                ty: entrypoint_value_type(&param.name, &param.ty)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let schema = ivm_abi::entrypoint::EntrypointArgumentSchemaV1 { fields };
    if !schema.validate() {
        return Err(format!(
            "entrypoint exceeds the ABI v1 limit of {} source parameters and {} flattened words",
            ivm_abi::entrypoint::MAX_ENTRYPOINT_ARGUMENTS,
            ivm_abi::entrypoint::MAX_ENTRYPOINT_ARGUMENT_WORDS,
        ));
    }
    Ok(Some(schema))
}
fn register_state_value_metadata(ctx: &mut LowerCtx, name: &str, ty: &Type, literal: &str) {
    ctx.state_name_literals
        .insert(name.to_string(), literal.to_string());
    let resolved = semantic::resolve_struct_type(ty);
    match &resolved {
        Type::StateMap(k, v) => {
            let key_ty = semantic::resolve_struct_type(k);
            let value_ty = semantic::resolve_struct_type(v);
            ctx.state_map_configs.insert(
                name.to_string(),
                StateMapSpec {
                    key: key_ty,
                    value: value_ty,
                },
            );
        }
        Type::Struct { .. } | Type::Tuple(_) | Type::Option(_) | Type::Result(_, _) => {}
        _ => {}
    }
}
fn push_copy(block: &mut BasicBlock, dest: Temp, src: Temp) {
    if dest == src {
        return;
    }
    block.instrs.push(Instr::Copy { dest, src });
}
/// The environment and predecessor block produced by one conditional arm.
struct ConditionalExit<'a> {
    env: &'a HashMap<String, Temp>,
    block: usize,
}

fn merge_conditional_envs(
    ctx: &mut LowerCtx,
    entry_env: &HashMap<String, Temp>,
    then_branch: ConditionalExit<'_>,
    else_branch: ConditionalExit<'_>,
    join_label: Label,
    vars: &mut HashMap<String, Temp>,
) {
    let ConditionalExit {
        env: then_env,
        block: then_exit,
    } = then_branch;
    let ConditionalExit {
        env: else_env,
        block: else_exit,
    } = else_branch;
    let mut products = Vec::new();
    let mut mutated = BTreeSet::new();
    for (name, entry_temp) in entry_env {
        let then_temp = then_env.get(name).copied().unwrap_or(*entry_temp);
        let else_temp = else_env.get(name).copied().unwrap_or(*entry_temp);
        if then_temp != *entry_temp || else_temp != *entry_temp {
            mutated.insert(name.clone());
        }
    }
    for name in mutated {
        let entry_temp = entry_env
            .get(&name)
            .copied()
            .expect("entry env must contain variable");
        let then_temp = then_env.get(&name).copied().unwrap_or(entry_temp);
        let else_temp = else_env.get(&name).copied().unwrap_or(entry_temp);
        if let Some(ty) = ctx.product_binding_type(&name) {
            let words = runtime_value_word_types(&ty)
                .into_iter()
                .map(|_| ctx.new_temp())
                .collect::<Vec<_>>();
            copy_runtime_value_words_to_block(ctx, then_exit, then_temp, &ty, &words);
            copy_runtime_value_words_to_block(ctx, else_exit, else_temp, &ty, &words);
            products.push((name, ty, words));
            continue;
        }
        let join_temp = ctx.new_temp();
        if let Some(block) = ctx.blocks.get_mut(then_exit) {
            push_copy(block, join_temp, then_temp);
        }
        if let Some(block) = ctx.blocks.get_mut(else_exit) {
            push_copy(block, join_temp, else_temp);
        }
        vars.insert(name, join_temp);
    }
    ctx.start_block(join_label);
    for (name, ty, words) in products {
        let value = rebuild_runtime_value(ctx, &ty, &words);
        vars.insert(name, value);
    }
}
/// Append a predecessor's scalar copies before its existing terminator. Virtual
/// products have no machine register, so a join must carry their actual words.
fn copy_runtime_value_words_to_block(
    ctx: &mut LowerCtx,
    block: usize,
    value: Temp,
    ty: &Type,
    words: &[Temp],
) {
    let label = ctx.blocks[block].label;
    let current = ctx.current.take();
    ctx.current = Some(BasicBlock {
        label,
        instrs: Vec::new(),
        terminator: Terminator::Jump(label),
    });
    copy_runtime_value_words(ctx, value, ty, words);
    let copies = ctx.current.take().expect("copy block").instrs;
    ctx.current = current;
    ctx.blocks[block].instrs.extend(copies);
}
fn collect_expr_reads(expr: &TypedExpr, reads: &mut BTreeSet<String>) {
    match expr.kind() {
        semantic::ExprKind::Binary { left, right, .. } => {
            collect_expr_reads(left, reads);
            collect_expr_reads(right, reads);
        }
        semantic::ExprKind::Unary { expr, .. }
        | semantic::ExprKind::NumericCast { expr }
        | semantic::ExprKind::NumericTryCast { expr } => {
            collect_expr_reads(expr, reads);
        }
        semantic::ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_expr_reads(cond, reads);
            collect_expr_reads(then_expr, reads);
            collect_expr_reads(else_expr, reads);
        }
        semantic::ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_expr_reads(condition, reads);
            collect_block_reads(then_branch, reads);
            collect_block_reads(else_branch, reads);
        }
        semantic::ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_expr_reads(value, reads);
            collect_block_reads(then_branch, reads);
            collect_block_reads(else_branch, reads);
        }
        semantic::ExprKind::Match { value, arms } => {
            collect_expr_reads(value, reads);
            for arm in arms {
                collect_block_reads(&arm.body, reads);
            }
        }
        semantic::ExprKind::JsonObject(entries) => {
            for (_, value) in entries {
                collect_expr_reads(value, reads);
            }
        }
        semantic::ExprKind::JsonArray(elements) => {
            for element in elements {
                collect_expr_reads(element, reads);
            }
        }
        semantic::ExprKind::OptionSome { value }
        | semantic::ExprKind::ResultOk { value }
        | semantic::ExprKind::ResultErr { error: value }
        | semantic::ExprKind::Propagate { value } => collect_expr_reads(value, reads),
        semantic::ExprKind::Call { args, .. }
        | semantic::ExprKind::NamedCall { args, .. }
        | semantic::ExprKind::Tuple(args)
        | semantic::ExprKind::List(args) => {
            for arg in args {
                collect_expr_reads(arg, reads);
            }
        }
        semantic::ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            collect_expr_reads(source, reads);
            collect_expr_reads(expression, reads);
            if let Some(condition) = condition {
                collect_expr_reads(condition, reads);
            }
        }
        semantic::ExprKind::StructLiteral { fields, .. } => {
            for (_, value) in fields {
                collect_expr_reads(value, reads);
            }
        }
        semantic::ExprKind::Member { object, .. } => collect_expr_reads(object, reads),
        semantic::ExprKind::Index { target, index } => {
            collect_expr_reads(target, reads);
            collect_expr_reads(index, reads);
        }
        semantic::ExprKind::Ident(name) => {
            reads.insert(name.clone());
        }
        semantic::ExprKind::VariantCode(_)
        | semantic::ExprKind::IntLiteral(_)
        | semantic::ExprKind::DecimalLiteral { .. }
        | semantic::ExprKind::Bool(_)
        | semantic::ExprKind::String(_)
        | semantic::ExprKind::Bytes(_)
        | semantic::ExprKind::OptionNone => {}
    }
}
fn collect_block_reads(block: &TypedBlock, reads: &mut BTreeSet<String>) {
    for statement in &block.statements {
        collect_statement_reads(statement, reads);
    }
    if let Some(tail) = &block.tail {
        collect_expr_reads(tail, reads);
    }
}
fn collect_statement_reads(statement: &TypedStatement, reads: &mut BTreeSet<String>) {
    match statement.kind() {
        TypedStatement::Let { value, .. } | TypedStatement::Expr(value) => {
            collect_expr_reads(value, reads);
        }
        TypedStatement::Return(Some(value)) => collect_expr_reads(value, reads),
        TypedStatement::Return(None) | TypedStatement::Break | TypedStatement::Continue => {}
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_expr_reads(cond, reads);
            collect_block_reads(then_branch, reads);
            if let Some(else_branch) = else_branch {
                collect_block_reads(else_branch, reads);
            }
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_expr_reads(value, reads);
            collect_block_reads(then_branch, reads);
            if let Some(else_branch) = else_branch {
                collect_block_reads(else_branch, reads);
            }
        }
        TypedStatement::While { cond, body } => {
            collect_expr_reads(cond, reads);
            collect_block_reads(body, reads);
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init) = init {
                collect_statement_reads(init, reads);
            }
            if let Some(cond) = cond {
                collect_expr_reads(cond, reads);
            }
            if let Some(step) = step {
                collect_statement_reads(step, reads);
            }
            collect_block_reads(body, reads);
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            collect_expr_reads(map, reads);
            collect_block_reads(body, reads);
        }
        TypedStatement::MapSet { map, key, value } => {
            collect_expr_reads(map, reads);
            collect_expr_reads(key, reads);
            collect_expr_reads(value, reads);
        }
    }
}
fn collect_block_mutations(block: &TypedBlock, mutations: &mut BTreeSet<String>) {
    for statement in &block.statements {
        collect_statement_mutations(statement, mutations);
    }
}
fn collect_statement_mutations(statement: &TypedStatement, mutations: &mut BTreeSet<String>) {
    match statement.kind() {
        TypedStatement::Let { name, .. } => {
            mutations.insert(name.clone());
        }
        TypedStatement::If {
            then_branch,
            else_branch,
            ..
        } => {
            collect_block_mutations(then_branch, mutations);
            if let Some(else_branch) = else_branch {
                collect_block_mutations(else_branch, mutations);
            }
        }
        TypedStatement::IfLet {
            then_branch,
            else_branch,
            ..
        } => {
            collect_block_mutations(then_branch, mutations);
            if let Some(else_branch) = else_branch {
                collect_block_mutations(else_branch, mutations);
            }
        }
        TypedStatement::While { body, .. } => collect_block_mutations(body, mutations),
        TypedStatement::For {
            init, step, body, ..
        } => {
            if let Some(init) = init {
                collect_statement_mutations(init, mutations);
            }
            if let Some(step) = step {
                collect_statement_mutations(step, mutations);
            }
            collect_block_mutations(body, mutations);
        }
        TypedStatement::ForEachMap {
            key, value, body, ..
        } => {
            mutations.insert(key.clone());
            if let Some(value) = value {
                mutations.insert(value.clone());
            }
            collect_block_mutations(body, mutations);
        }
        TypedStatement::Expr(_)
        | TypedStatement::Return(_)
        | TypedStatement::Break
        | TypedStatement::Continue
        | TypedStatement::MapSet { .. } => {}
    }
}
fn live_before_statement(
    statement: &TypedStatement,
    live_after: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut live = match statement.kind() {
        // A return has no fallthrough edge. Keeping only its expression reads
        // prevents unreachable trailing statements from extending lifetimes.
        TypedStatement::Return(_) => BTreeSet::new(),
        _ => live_after.clone(),
    };
    if let TypedStatement::Let { name, .. } = statement.kind() {
        live.remove(name);
    }
    collect_statement_reads(statement, &mut live);
    live
}
fn block_live_after_sets(
    block: &TypedBlock,
    outer_live_after: &BTreeSet<String>,
) -> Vec<BTreeSet<String>> {
    let mut live = outer_live_after.clone();
    if let Some(tail) = &block.tail {
        collect_expr_reads(tail, &mut live);
    }
    let mut result = vec![BTreeSet::new(); block.statements.len()];
    for (index, statement) in block.statements.iter().enumerate().rev() {
        result[index] = live.clone();
        live = if matches!(
            statement.kind(),
            TypedStatement::Break | TypedStatement::Continue
        ) {
            // Neither statement falls through to the remaining source block.
            // The caller supplies the union of loop-header and loop-exit
            // liveness, which is conservative for both target kinds.
            outer_live_after.clone()
        } else {
            live_before_statement(statement, &live)
        };
    }
    result
}
fn loop_phi_names(
    vars: &HashMap<String, Temp>,
    mutations: &BTreeSet<String>,
    loop_reads: &BTreeSet<String>,
    live_after: &BTreeSet<String>,
) -> BTreeSet<String> {
    mutations
        .iter()
        .filter(|name| {
            vars.contains_key(*name) && (loop_reads.contains(*name) || live_after.contains(*name))
        })
        .cloned()
        .collect()
}
fn initialize_loop_phi(
    ctx: &mut LowerCtx,
    vars: &HashMap<String, Temp>,
    names: &BTreeSet<String>,
) -> HashMap<String, Temp> {
    let mut phi = HashMap::new();
    for name in names {
        let Some(temp) = vars.get(name).copied() else {
            continue;
        };
        let slot = if let Some(ty) = ctx.product_binding_type(name) {
            let words = runtime_value_word_types(&ty)
                .into_iter()
                .map(|_| ctx.new_temp())
                .collect::<Vec<_>>();
            copy_runtime_value_words(ctx, temp, &ty, &words);
            // This handle is compiler metadata only. Each loop destination
            // rebuilds its virtual product from the words current on that edge.
            let value = ctx.new_temp();
            ctx.product_loop_phis.insert(value, (ty, words));
            value
        } else {
            let slot = ctx.new_temp();
            emit_copy(ctx, slot, temp);
            slot
        };
        phi.insert(name.clone(), slot);
    }
    phi
}
fn env_with_loop_phi(
    ctx: &mut LowerCtx,
    base: &HashMap<String, Temp>,
    phi: &HashMap<String, Temp>,
) -> HashMap<String, Temp> {
    let mut env = base.clone();
    apply_loop_phi(ctx, &mut env, phi);
    env
}
fn apply_loop_phi(
    ctx: &mut LowerCtx,
    env: &mut HashMap<String, Temp>,
    phi: &HashMap<String, Temp>,
) {
    let mut entries = phi.iter().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (name, temp) in entries {
        let value = if let Some((ty, words)) = ctx.product_loop_phis.get(temp).cloned() {
            rebuild_runtime_value(ctx, &ty, &words)
        } else {
            *temp
        };
        env.insert(name.clone(), value);
    }
}
fn copy_env_to_loop_phi(ctx: &mut LowerCtx, env: &HashMap<String, Temp>) {
    if let Some(phi) = ctx.current_loop_phi() {
        let mut copies: Vec<(Temp, Temp)> = Vec::new();
        let mut entries = phi.iter().collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (name, dest) in entries {
            if let Some(src) = env.get(name)
                && dest != src
            {
                copies.push((*dest, *src));
            }
        }
        // Read every carried value before writing any phi word: separately
        // rebound products can still share the previous iteration's leaves.
        let mut word_copies = Vec::new();
        for (dest, src) in copies {
            if let Some((ty, destinations)) = ctx.product_loop_phis.get(&dest).cloned() {
                let mut words = Vec::with_capacity(destinations.len());
                collect_function_value_words(ctx, src, &ty, &mut words);
                if words.len() != destinations.len() {
                    ctx.record_error("internal error: loop product word count mismatch".into());
                }
                word_copies.extend(destinations.into_iter().zip(words));
            } else {
                word_copies.push((dest, src));
            }
        }
        let destinations = word_copies
            .iter()
            .map(|(dest, _)| *dest)
            .collect::<HashSet<_>>();
        for (_, src) in &mut word_copies {
            if destinations.contains(src) {
                let captured = ctx.new_temp();
                emit_copy(ctx, captured, *src);
                *src = captured;
            }
        }
        for (dest, src) in word_copies {
            emit_copy(ctx, dest, src);
        }
    }
}
fn lower_block_with_live_after(
    ctx: &mut LowerCtx,
    block: &TypedBlock,
    vars: &mut HashMap<String, Temp>,
    outer_live_after: &BTreeSet<String>,
) {
    let _ = lower_block_tail_with_live_after(ctx, block, vars, outer_live_after);
}
fn lower_block_tail_with_live_after(
    ctx: &mut LowerCtx,
    block: &TypedBlock,
    vars: &mut HashMap<String, Temp>,
    outer_live_after: &BTreeSet<String>,
) -> Option<Temp> {
    let live_after = block_live_after_sets(block, outer_live_after);
    let enclosing_source = ctx.current_source;
    for (index, (statement, statement_live_after)) in
        block.statements.iter().zip(live_after.iter()).enumerate()
    {
        ctx.set_source(block.statement_source(index).or(enclosing_source));
        lower_statement(ctx, statement, vars, statement_live_after);
    }
    ctx.set_source(block.tail_source().or(enclosing_source));
    let value = block.tail.as_ref().map(|tail| lower_expr(ctx, tail, vars));
    ctx.set_source(enclosing_source);
    value
}
fn lower_expression_block(
    ctx: &mut LowerCtx,
    block: &TypedBlock,
    vars: &mut HashMap<String, Temp>,
) -> Option<Temp> {
    let value = lower_block_tail_with_live_after(ctx, block, vars, &BTreeSet::new());
    if semantic::typed_block_diverges(block) {
        // `return`, `break`, `continue`, or recursively divergent expression
        // lowering leaves a deliberately unreachable continuation current.
        // It must not become a fake branch value or a predecessor of the join.
        // Seal it so every constructed edge remains valid until SSA removes
        // the dead subgraph after enforcing the raw-lowering budget.
        seal_unreachable_continuation(ctx);
        return None;
    }
    Some(value.unwrap_or_else(|| emit_i64_const(ctx, 0)))
}
fn seal_unreachable_continuation(ctx: &mut LowerCtx) {
    if let Some(label) = ctx.current.as_ref().map(|block| block.label) {
        ctx.finish_current(Terminator::Jump(label));
    }
}
fn finish_value_return(ctx: &mut LowerCtx, value: Temp, ty: &Type) {
    if function_value_word_types(ty).is_some() {
        let mut outs = Vec::new();
        collect_function_value_words(ctx, value, ty, &mut outs);
        match outs.as_slice() {
            [] => ctx.finish_current(Terminator::Return(None)),
            [only] => ctx.finish_current(Terminator::Return(Some(*only))),
            [first, second] => ctx.finish_current(Terminator::Return2(*first, *second)),
            _ => ctx.finish_current(Terminator::ReturnN(outs)),
        }
    } else {
        ctx.finish_current(Terminator::Return(Some(value)));
    }
}
fn lower_statement(
    ctx: &mut LowerCtx,
    stmt: &TypedStatement,
    vars: &mut HashMap<String, Temp>,
    live_after: &BTreeSet<String>,
) {
    match stmt {
        TypedStatement::Let { name, value } => {
            ctx.binding_types.insert(name.clone(), value.ty.clone());
            let t = lower_expr(ctx, value, vars);
            // A product rebind replaces every flattened projection of its old
            // value. Following field bindings must read the newly captured root.
            if matches!(
                semantic::resolve_struct_type(&value.ty),
                Type::Struct { .. } | Type::Tuple(_)
            ) {
                let projection_prefix = format!("{name}#");
                vars.retain(|binding, _| !binding.starts_with(&projection_prefix));
            }
            if ctx.state_name_literals.contains_key(name)
                || ctx.state_runtime_roots.contains_key(name)
            {
                emit_state_set(ctx, name, &value.ty, t);
                ctx.state_value_cache.insert(name.clone(), t);
            } else {
                vars.insert(name.clone(), t);
            }
        }
        TypedStatement::Expr(e) => {
            let _ = lower_expr(ctx, e, vars);
        }
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            let entry_env = vars.clone();
            let cond_t = lower_expr(ctx, cond, vars);
            let then_label = ctx.new_label();
            let else_label = ctx.new_label();
            let end_label = ctx.new_label();
            ctx.finish_current(Terminator::Branch {
                cond: cond_t,
                then_bb: then_label,
                else_bb: else_label,
            });
            ctx.start_block(then_label);
            let mut then_vars = entry_env.clone();
            lower_block_with_live_after(ctx, then_branch, &mut then_vars, live_after);
            ctx.finish_current(Terminator::Jump(end_label));
            let then_idx = ctx.blocks.len() - 1;
            ctx.start_block(else_label);
            let mut else_vars = entry_env.clone();
            if let Some(b) = else_branch {
                lower_block_with_live_after(ctx, b, &mut else_vars, live_after);
            }
            ctx.finish_current(Terminator::Jump(end_label));
            let else_idx = ctx.blocks.len() - 1;
            merge_conditional_envs(
                ctx,
                &entry_env,
                ConditionalExit {
                    env: &then_vars,
                    block: then_idx,
                },
                ConditionalExit {
                    env: &else_vars,
                    block: else_idx,
                },
                end_label,
                vars,
            );
        }
        TypedStatement::IfLet {
            pattern,
            value,
            then_branch,
            else_branch,
        } => {
            let entry_env = vars.clone();
            let sum = lower_expr(ctx, value, vars);
            let then_label = ctx.new_label();
            let else_label = ctx.new_label();
            let end_label = ctx.new_label();
            branch_on_sum_pattern(ctx, pattern, sum, then_label, else_label);
            ctx.start_block(then_label);
            let mut then_vars = entry_env.clone();
            bind_sum_pattern(ctx, pattern, sum, &mut then_vars);
            lower_block_with_live_after(ctx, then_branch, &mut then_vars, live_after);
            ctx.finish_current(Terminator::Jump(end_label));
            let then_idx = ctx.blocks.len() - 1;
            ctx.start_block(else_label);
            let mut else_vars = entry_env.clone();
            if let Some(else_branch) = else_branch {
                lower_block_with_live_after(ctx, else_branch, &mut else_vars, live_after);
            }
            ctx.finish_current(Terminator::Jump(end_label));
            let else_idx = ctx.blocks.len() - 1;
            merge_conditional_envs(
                ctx,
                &entry_env,
                ConditionalExit {
                    env: &then_vars,
                    block: then_idx,
                },
                ConditionalExit {
                    env: &else_vars,
                    block: else_idx,
                },
                end_label,
                vars,
            );
        }
        TypedStatement::While { cond, body } => {
            let cond_label = ctx.new_label();
            let body_label = ctx.new_label();
            let end_label = ctx.new_label();
            let entry_vars = vars.clone();
            let mut mutations = BTreeSet::new();
            collect_block_mutations(body, &mut mutations);
            let mut loop_reads = BTreeSet::new();
            collect_expr_reads(cond, &mut loop_reads);
            collect_block_reads(body, &mut loop_reads);
            let phi_names = loop_phi_names(vars, &mutations, &loop_reads, live_after);
            let loop_phi = initialize_loop_phi(ctx, vars, &phi_names);
            ctx.push_loop(cond_label, end_label);
            ctx.set_loop_phi(loop_phi.clone());
            ctx.finish_current(Terminator::Jump(cond_label));
            ctx.start_block(cond_label);
            let mut cond_vars = env_with_loop_phi(ctx, &entry_vars, &loop_phi);
            let cond_t = lower_expr(ctx, cond, &mut cond_vars);
            ctx.finish_current(Terminator::Branch {
                cond: cond_t,
                then_bb: body_label,
                else_bb: end_label,
            });
            ctx.start_block(body_label);
            let mut body_vars = cond_vars;
            let mut body_live_after = loop_reads;
            body_live_after.extend(live_after.iter().cloned());
            lower_block_with_live_after(ctx, body, &mut body_vars, &body_live_after);
            copy_env_to_loop_phi(ctx, &body_vars);
            ctx.finish_current(Terminator::Jump(cond_label));
            ctx.pop_loop();
            ctx.start_block(end_label);
            *vars = entry_vars;
            apply_loop_phi(ctx, vars, &loop_phi);
        }
        TypedStatement::For {
            line: _,
            init,
            cond,
            step,
            body,
        } => {
            if let Some(s) = init {
                lower_statement(ctx, s, vars, &BTreeSet::new());
            }
            let cond_label = ctx.new_label();
            let body_label = ctx.new_label();
            let step_label = ctx.new_label();
            let end_label = ctx.new_label();
            let entry_vars = vars.clone();
            let mut mutations = BTreeSet::new();
            collect_block_mutations(body, &mut mutations);
            if let Some(step) = step {
                collect_statement_mutations(step, &mut mutations);
            }
            let mut loop_reads = BTreeSet::new();
            if let Some(cond) = cond {
                collect_expr_reads(cond, &mut loop_reads);
            }
            if let Some(step) = step {
                collect_statement_reads(step, &mut loop_reads);
            }
            collect_block_reads(body, &mut loop_reads);
            let phi_names = loop_phi_names(vars, &mutations, &loop_reads, live_after);
            let loop_phi = initialize_loop_phi(ctx, vars, &phi_names);
            ctx.push_loop(step_label, end_label);
            ctx.set_loop_phi(loop_phi.clone());
            ctx.finish_current(Terminator::Jump(cond_label));
            ctx.start_block(cond_label);
            let mut cond_vars = env_with_loop_phi(ctx, &entry_vars, &loop_phi);
            let cond_t = if let Some(c) = cond {
                lower_expr(ctx, c, &mut cond_vars)
            } else {
                emit_i64_const(ctx, 1)
            };
            ctx.finish_current(Terminator::Branch {
                cond: cond_t,
                then_bb: body_label,
                else_bb: end_label,
            });
            ctx.start_block(body_label);
            let mut body_vars = cond_vars;
            let mut body_live_after = loop_reads.clone();
            body_live_after.extend(live_after.iter().cloned());
            lower_block_with_live_after(ctx, body, &mut body_vars, &body_live_after);
            copy_env_to_loop_phi(ctx, &body_vars);
            ctx.finish_current(Terminator::Jump(step_label));
            ctx.start_block(step_label);
            if let Some(s) = step {
                let mut step_vars = env_with_loop_phi(ctx, &entry_vars, &loop_phi);
                lower_statement(ctx, s, &mut step_vars, &body_live_after);
                copy_env_to_loop_phi(ctx, &step_vars);
            }
            ctx.finish_current(Terminator::Jump(cond_label));
            ctx.pop_loop();
            ctx.start_block(end_label);
            *vars = entry_vars;
            apply_loop_phi(ctx, vars, &loop_phi);
        }
        TypedStatement::Break => {
            if let Some((_, brk)) = ctx.loop_targets() {
                copy_env_to_loop_phi(ctx, vars);
                ctx.finish_current(Terminator::Jump(brk));
                let cont = ctx.new_label();
                ctx.start_block(cont);
            }
        }
        TypedStatement::Continue => {
            if let Some((cont, _)) = ctx.loop_targets() {
                copy_env_to_loop_phi(ctx, vars);
                ctx.finish_current(Terminator::Jump(cont));
                let next = ctx.new_label();
                ctx.start_block(next);
            }
        }
        TypedStatement::Return(opt) => {
            if let Some(e) = opt {
                let value = lower_expr(ctx, e, vars);
                finish_value_return(ctx, value, &e.ty);
            } else {
                let unit = emit_i64_const(ctx, 0);
                ctx.finish_current(Terminator::Return(Some(unit)));
            }
            // Start a fresh (unreachable) block to continue lowering subsequent statements gracefully
            let cont = ctx.new_label();
            ctx.start_block(cont);
        }
        TypedStatement::ForEachMap {
            key,
            value,
            map,
            body,
        } => {
            let Type::List(element, _) = semantic::resolve_struct_type(&map.ty) else {
                ctx.record_error("internal error: bounded iteration requires a List".into());
                return;
            };
            debug_assert!(value.is_none());
            let base = lower_expr(ctx, map, vars);
            let limit = emit_load64_imm(ctx, base, 0);
            let index = emit_i64_const(ctx, 0);
            let one = emit_i64_const(ctx, 1);
            let loop_label = ctx.new_label();
            let body_label = ctx.new_label();
            let step_label = ctx.new_label();
            let exit_label = ctx.new_label();
            let entry_vars = vars.clone();
            let mut mutations = BTreeSet::new();
            collect_block_mutations(body, &mut mutations);
            let mut loop_reads = BTreeSet::new();
            collect_block_reads(body, &mut loop_reads);
            let phi_names = loop_phi_names(vars, &mutations, &loop_reads, live_after);
            let loop_phi = initialize_loop_phi(ctx, vars, &phi_names);
            ctx.push_loop(step_label, exit_label);
            ctx.set_loop_phi(loop_phi.clone());
            ctx.finish_current(Terminator::Jump(loop_label));
            ctx.start_block(loop_label);
            let cond_t = emit_binary(ctx, BinaryOp::Lt, index, limit);
            ctx.finish_current(Terminator::Branch {
                cond: cond_t,
                then_bb: body_label,
                else_bb: exit_label,
            });
            ctx.start_block(body_label);
            let mut body_vars = env_with_loop_phi(ctx, &entry_vars, &loop_phi);
            let key_temp = load_list_element(ctx, base, index, &element);
            body_vars.insert(key.clone(), key_temp);
            let mut body_live_after = loop_reads;
            body_live_after.extend(live_after.iter().cloned());
            lower_block_with_live_after(ctx, body, &mut body_vars, &body_live_after);
            copy_env_to_loop_phi(ctx, &body_vars);
            ctx.finish_current(Terminator::Jump(step_label));
            ctx.start_block(step_label);
            ctx.current_instr(Instr::Binary {
                dest: index,
                op: BinaryOp::Add,
                left: index,
                right: one,
            });
            ctx.finish_current(Terminator::Jump(loop_label));
            ctx.pop_loop();
            ctx.start_block(exit_label);
            *vars = entry_vars;
            apply_loop_phi(ctx, vars, &loop_phi);
        }
        TypedStatement::MapSet { map, key, value } => {
            let key_tmp = lower_expr(ctx, key, vars);
            let value_tmp = lower_expr(ctx, value, vars);
            if let Some(bn) = state_map_base_name(map)
                && let Some(spec) = ctx.state_map_configs.get(&bn).cloned()
            {
                let _ =
                    lower_state_map_set_value(ctx, &bn, key_tmp, &spec.key, &spec.value, value_tmp);
                return;
            }
            let m = lower_expr(ctx, map, vars);
            ctx.current_instr(Instr::MapSet {
                map: m,
                key: key_tmp,
                value: value_tmp,
            });
        }
    }
}
fn decode_state_map_key(ctx: &mut LowerCtx, key_blob: Temp, key_ty: &Type) -> Option<Temp> {
    state_map_key_type(key_ty)?;
    decode_aggregate_state_value(ctx, key_blob, key_ty)
}
fn lower_state_page_intrinsic(
    ctx: &mut LowerCtx,
    name: CompilerIntrinsic,
    args: &[TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Option<Temp> {
    if !matches!(
        name,
        CompilerIntrinsic::StatePage | CompilerIntrinsic::StateTake
    ) {
        return None;
    }
    let base_name = state_map_base_name(&args[0]).expect("validated declared StateMap scan");
    let Type::StateMap(key_ty, value_ty) = semantic::resolve_struct_type(&args[0].ty) else {
        unreachable!("validated StateMap scan receiver");
    };
    let take = name == CompilerIntrinsic::StateTake;
    let list_ty = if take {
        result_ty.clone()
    } else {
        let Type::Struct { fields, .. } = semantic::resolve_struct_type(result_ty) else {
            unreachable!("validated StatePage result");
        };
        fields[0].1.clone()
    };
    let option_ty = args[1].ty.clone();
    let option = lower_expr(ctx, &args[1], vars);
    let tag = load_sum_tag(ctx, option);
    let after = ctx.new_temp();
    let some_bb = ctx.new_label();
    let none_bb = ctx.new_label();
    let scan_bb = ctx.new_label();
    ctx.finish_current(Terminator::Branch {
        cond: tag,
        then_bb: some_bb,
        else_bb: none_bb,
    });
    ctx.start_block(some_bb);
    let cursor = load_sum_payload(ctx, option, &Type::StateCursor(key_ty.clone()));
    ctx.current_instr(Instr::Copy {
        dest: after,
        src: cursor,
    });
    ctx.finish_current(Terminator::Jump(scan_bb));
    ctx.start_block(none_bb);
    let zero = emit_i64_const(ctx, 0);
    ctx.current_instr(Instr::Copy {
        dest: after,
        src: zero,
    });
    ctx.finish_current(Terminator::Jump(scan_bb));
    ctx.start_block(scan_bb);
    let limit = lower_expr_as_u64(ctx, &args[2], vars);
    let path = build_state_root_path(ctx, &base_name);
    let base = build_state_base_name(ctx, &base_name);
    let page = ctx.new_temp();
    let next = ctx.new_temp();
    let count = ctx.new_temp();
    let examined = ctx.new_temp();
    ctx.current_instr(Instr::StateScan {
        page,
        next,
        count,
        examined,
        base: path,
        after,
        limit,
        dynamic_access_hint: DynamicAccessHint {
            base_key: format!(
                "{}{base_name}",
                kotodama_surface::source_policy::V1_DYNAMIC_ACCESS_BASE_PREFIX
            ),
            key_type: semantic::type_name(&key_ty),
            bound_kind: if take { "take" } else { "page" }.into(),
            max_keys: 64,
        },
    });
    let items = emit_list_allocation(ctx, &list_ty, 0);
    emit_store64_imm(ctx, items, 0, count);
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    let loop_label = ctx.new_label();
    let body_label = ctx.new_label();
    let exit_label = ctx.new_label();
    ctx.finish_current(Terminator::Jump(loop_label));
    ctx.start_block(loop_label);
    let cond_t = emit_binary(ctx, BinaryOp::Lt, index, count);
    ctx.finish_current(Terminator::Branch {
        cond: cond_t,
        then_bb: body_label,
        else_bb: exit_label,
    });
    ctx.start_block(body_label);
    let key_blob = ctx.new_temp();
    ctx.current_instr(Instr::StateMapKeyAt {
        dest: key_blob,
        page,
        base,
        index,
    });
    let key_temp =
        decode_state_map_key(ctx, key_blob, &key_ty).expect("validated StateMap key decoder");
    let value_temp = lower_state_map_get_value(ctx, &base_name, key_temp, &key_ty, &value_ty)
        .expect("validated StateMap value decoder");
    let element = Type::Tuple(vec![*key_ty, *value_ty]);
    let pair = emit_tuple_pack(ctx, vec![key_temp, value_temp]);
    store_list_element(ctx, items, index, pair, &element);
    ctx.current_instr(Instr::Binary {
        dest: index,
        op: BinaryOp::Add,
        left: index,
        right: one,
    });
    ctx.finish_current(Terminator::Jump(loop_label));
    ctx.start_block(exit_label);
    if take {
        return Some(items);
    }
    let some_bb = ctx.new_label();
    let none_bb = ctx.new_label();
    let end_bb = ctx.new_label();
    let continuation = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: next,
        then_bb: some_bb,
        else_bb: none_bb,
    });
    ctx.start_block(some_bb);
    let some = emit_sum_value(ctx, &option_ty, 1, Some(next));
    ctx.current_instr(Instr::Copy {
        dest: continuation,
        src: some,
    });
    ctx.finish_current(Terminator::Jump(end_bb));
    ctx.start_block(none_bb);
    let none = emit_sum_value(ctx, &option_ty, 0, None);
    ctx.current_instr(Instr::Copy {
        dest: continuation,
        src: none,
    });
    ctx.finish_current(Terminator::Jump(end_bb));
    ctx.start_block(end_bb);
    Some(emit_tuple_pack(ctx, vec![items, continuation]))
}
fn lower_expr_as_i64(
    ctx: &mut LowerCtx,
    expr: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    if let semantic::ExprKind::IntLiteral(value) = expr.kind() {
        if let Some(value) = value.try_to_i64() {
            return emit_i64_const(ctx, value);
        }
        ctx.record_error(format!(
            "constant `{value}` is outside the signed 64-bit range required by this host boundary"
        ));
        return emit_i64_const(ctx, 0);
    }
    let value = lower_expr(ctx, expr, vars);
    if matches!(semantic::resolve_struct_type(&expr.ty), Type::Int) {
        let out = ctx.new_temp();
        ctx.current_instr(Instr::IntToI64 { dest: out, value });
        out
    } else {
        value
    }
}
fn lower_expr_as_u64(
    ctx: &mut LowerCtx,
    expr: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    if let semantic::ExprKind::IntLiteral(value) = expr.kind() {
        if let Some(value) = value.try_to_u64() {
            return emit_i64_const(ctx, i64::from_le_bytes(value.to_le_bytes()));
        }
        ctx.record_error(format!(
            "constant `{value}` is outside the unsigned 64-bit range required by this host boundary"
        ));
        return emit_i64_const(ctx, 0);
    }
    let value = lower_expr(ctx, expr, vars);
    if matches!(semantic::resolve_struct_type(&expr.ty), Type::Int) {
        let out = ctx.new_temp();
        ctx.current_instr(Instr::IntToU64 { dest: out, value });
        out
    } else {
        value
    }
}
fn lower_expr_as_numeric(
    ctx: &mut LowerCtx,
    expr: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let value = lower_expr(ctx, expr, vars);
    if !matches!(semantic::resolve_struct_type(&expr.ty), Type::Quantity) {
        ctx.record_error(format!(
            "ledger quantity boundary received {}; use quantity::try_from_decimal and handle its status first",
            semantic::type_name(&expr.ty)
        ));
    }
    value
}
/// Select a source builtin's direct host operation exclusively through its
/// canonical registry record.
///
/// This is deliberately fail-closed: passing an instruction-only or derived builtin is a compiler
/// invariant violation, not an opportunity for lowering to invent an unregistered syscall number.
fn direct_builtin_syscall(builtin: Builtin) -> u32 {
    let spec = builtin.spec();
    assert_eq!(
        spec.lowering,
        BuiltinLowering::DirectSyscall,
        "IR lowering requested a direct syscall for non-direct builtin {}",
        spec.name
    );
    spec.syscall.unwrap_or_else(|| {
        panic!(
            "direct builtin {} has no syscall in the canonical registry",
            spec.name
        )
    })
}
fn numeric_binary_builtin_op(builtin: Builtin) -> Option<BinaryOp> {
    Some(match builtin {
        Builtin::NumericAdd => BinaryOp::Add,
        Builtin::NumericSub => BinaryOp::Sub,
        Builtin::NumericMul => BinaryOp::Mul,
        Builtin::NumericDiv => BinaryOp::Div,
        Builtin::NumericRem => BinaryOp::Mod,
        _ => return None,
    })
}
fn numeric_compare_builtin_op(builtin: Builtin) -> Option<BinaryOp> {
    Some(match builtin {
        Builtin::NumericEq => BinaryOp::Eq,
        Builtin::NumericNe => BinaryOp::Ne,
        Builtin::NumericLt => BinaryOp::Lt,
        Builtin::NumericLe => BinaryOp::Le,
        Builtin::NumericGt => BinaryOp::Gt,
        Builtin::NumericGe => BinaryOp::Ge,
        _ => return None,
    })
}
fn lower_hash_builtin_call(
    ctx: &mut LowerCtx,
    builtin: Builtin,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let message = lower_expr(ctx, &args[0], vars);
    let dest = ctx.new_temp();
    let instr = match builtin {
        Builtin::Sm3Hash => Instr::Sm3Hash { dest, message },
        Builtin::Sha256Hash => Instr::Sha256Hash { dest, message },
        Builtin::Sha3Hash => Instr::Sha3Hash { dest, message },
        Builtin::Blake2b256Hash => Instr::Blake2b256Hash { dest, message },
        Builtin::Keccak256Hash => Instr::Keccak256Hash { dest, message },
        Builtin::IrohaHash => Instr::IrohaHash { dest, message },
        _ => unreachable!("non-hash builtin passed to lower_hash_builtin_call"),
    };
    ctx.current_instr(instr);
    dest
}
fn lower_signature_builtin_call(
    ctx: &mut LowerCtx,
    builtin: Builtin,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let message = lower_expr(ctx, &args[0], vars);
    let signature = lower_expr(ctx, &args[1], vars);
    let public_key = lower_expr(ctx, &args[2], vars);
    let dest = ctx.new_temp();
    match builtin {
        Builtin::Sm2Verify => {
            let distid = args.get(3).map(|arg| lower_expr(ctx, arg, vars));
            ctx.current_instr(Instr::Sm2Verify {
                dest,
                message,
                signature,
                public_key,
                distid,
            });
        }
        Builtin::VerifySignature => {
            // Semantic analysis folds the `SignatureScheme::*` argument into
            // its host scheme code, so no runtime value can name another scheme.
            let scheme = match args.get(3).map(semantic::TypedExpr::kind) {
                Some(semantic::ExprKind::IntLiteral(code)) => {
                    emit_i64_const(ctx, code.try_to_i64().unwrap_or(0))
                }
                _ => {
                    ctx.record_error(
                        "internal error: signature scheme was not folded to its host code".into(),
                    );
                    emit_i64_const(ctx, 0)
                }
            };
            ctx.current_instr(Instr::VerifySignature {
                dest,
                message,
                signature,
                public_key,
                scheme,
            });
        }
        _ => unreachable!("non-signature builtin passed to lower_signature_builtin_call"),
    }
    dest
}
fn lower_sm4_builtin_call(
    ctx: &mut LowerCtx,
    builtin: Builtin,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let key = lower_expr(ctx, &args[0], vars);
    let nonce = lower_expr(ctx, &args[1], vars);
    let aad = lower_expr(ctx, &args[2], vars);
    let data = lower_expr(ctx, &args[3], vars);
    let dest = ctx.new_temp();
    match builtin {
        Builtin::Sm4GcmSeal => ctx.current_instr(Instr::Sm4GcmSeal {
            dest,
            key,
            nonce,
            aad,
            plaintext: data,
        }),
        Builtin::Sm4GcmOpen => ctx.current_instr(Instr::Sm4GcmOpen {
            dest,
            key,
            nonce,
            aad,
            ciphertext_and_tag: data,
        }),
        Builtin::Sm4CcmSeal => {
            let tag_len = args.get(4).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            ctx.current_instr(Instr::Sm4CcmSeal {
                dest,
                key,
                nonce,
                aad,
                plaintext: data,
                tag_len,
            });
        }
        Builtin::Sm4CcmOpen => {
            let tag_len = args.get(4).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            ctx.current_instr(Instr::Sm4CcmOpen {
                dest,
                key,
                nonce,
                aad,
                ciphertext_and_tag: data,
                tag_len,
            });
        }
        _ => unreachable!("non-SM4 builtin passed to lower_sm4_builtin_call"),
    }
    dest
}
/// Exact numeric selection keeps the source domain and evaluates every argument once.
fn lower_numeric_selection(
    ctx: &mut LowerCtx,
    builtin: Builtin,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let kind = wide_numeric_kind_for_type(&args[0].ty).expect("typed selection operand");
    let values = args
        .iter()
        .map(|arg| lower_expr(ctx, arg, vars))
        .collect::<Vec<_>>();
    if kind == WideNumericKind::Int {
        let syscall = match builtin {
            Builtin::Min => ivm_abi::syscalls::SYSCALL_INT_MIN,
            Builtin::Max => ivm_abi::syscalls::SYSCALL_INT_MAX,
            Builtin::Abs => ivm_abi::syscalls::SYSCALL_INT_ABS,
            _ => unreachable!("numeric selection builtin"),
        };
        let dest = ctx.new_temp();
        ctx.current_instr(Instr::DirectHelperSyscall {
            dest,
            syscall,
            args: values,
        });
        return dest;
    }
    if builtin == Builtin::Abs && kind == WideNumericKind::Quantity {
        return values[0];
    }
    let right = if builtin == Builtin::Abs {
        emit_data_ref(ctx, DataRefKind::Decimal, "0".into())
    } else {
        values[1]
    };
    let less = emit_numeric_compare(ctx, BinaryOp::Lt, values[0], right, kind);
    let yes = ctx.new_label();
    let no = ctx.new_label();
    let end = ctx.new_label();
    let output = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: less,
        then_bb: yes,
        else_bb: no,
    });
    ctx.start_block(yes);
    let selected = match builtin {
        Builtin::Abs => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NumericNeg {
                dest,
                value: values[0],
                kind,
            });
            dest
        }
        Builtin::Min => values[0],
        Builtin::Max => right,
        _ => unreachable!("numeric selection builtin"),
    };
    emit_copy(ctx, output, selected);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(no);
    emit_copy(
        ctx,
        output,
        if builtin == Builtin::Min {
            right
        } else {
            values[0]
        },
    );
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    output
}
fn lower_direct_helper_call(
    ctx: &mut LowerCtx,
    builtin: Builtin,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let syscall = direct_builtin_syscall(builtin);
    let mut lowered_args = Vec::with_capacity(args.len());
    for arg in args {
        lowered_args.push(lower_expr(ctx, arg, vars));
    }
    let dest = ctx.new_temp();
    ctx.current_instr(Instr::DirectHelperSyscall {
        dest,
        syscall,
        args: lowered_args,
    });
    dest
}
fn pointer_constructor_kind_and_type(constructor: PointerConstructor) -> (DataRefKind, Type) {
    match constructor {
        PointerConstructor::AccountId => (DataRefKind::Account, Type::AccountId),
        PointerConstructor::AssetDefinition => (DataRefKind::AssetDef, Type::AssetDefinitionId),
        PointerConstructor::AssetId => (DataRefKind::AssetId, Type::AssetId),
        PointerConstructor::NftId => (DataRefKind::NftId, Type::NftId),
        PointerConstructor::Domain | PointerConstructor::DomainId => {
            (DataRefKind::Domain, Type::DomainId)
        }
        PointerConstructor::Name => (DataRefKind::Name, Type::Name),
        PointerConstructor::Json => (DataRefKind::Json, Type::Json),
        PointerConstructor::Blob => (DataRefKind::Blob, Type::Bytes),
        PointerConstructor::NoritoBytes => (DataRefKind::NoritoBytes, Type::Bytes),
        PointerConstructor::DataSpaceId => (DataRefKind::DataSpaceId, Type::DataSpaceId),
        PointerConstructor::AxtDescriptor => (DataRefKind::AxtDescriptor, Type::AxtDescriptor),
        PointerConstructor::AxtAnchoredSpendV1 => {
            (DataRefKind::AxtAnchoredSpendV1, Type::AxtAnchoredSpendV1)
        }
        PointerConstructor::ProofBlob => (DataRefKind::ProofBlob, Type::ProofBlob),
        PointerConstructor::SoracloudRequest => {
            (DataRefKind::SoracloudRequest, Type::SoracloudRequest)
        }
        PointerConstructor::SoracloudResponse => {
            (DataRefKind::SoracloudResponse, Type::SoracloudResponse)
        }
    }
}
fn lower_pointer_constructor_call(
    ctx: &mut LowerCtx,
    constructor: PointerConstructor,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    if args.len() != 1 {
        let t = ctx.new_temp();
        ctx.current_instr(Instr::Const { dest: t, value: 0 });
        return t;
    }
    let arg = &args[0];
    let (kind, target_ty) = pointer_constructor_kind_and_type(constructor);
    if let semantic::ExprKind::String(s) = arg.kind() {
        if constructor == PointerConstructor::AccountId
            && account_id_literal_uses_alias_resolution(s)
        {
            let alias = emit_data_ref(ctx, DataRefKind::Blob, s.clone());
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ResolveAccountAlias { dest, alias });
            return dest;
        }
        let dest = emit_data_ref(ctx, kind, s.clone());
        return dest;
    }
    if constructor == PointerConstructor::NoritoBytes
        && let semantic::ExprKind::Bytes(bytes) = arg.kind()
    {
        let dest = ctx.new_temp();
        let hex = hex::encode(bytes);
        emit_data_ref_into(ctx, dest, DataRefKind::NoritoBytes, format!("0x{hex}"));
        return dest;
    }
    let src = lower_expr(ctx, arg, vars);
    let resolved_arg = semantic::resolve_struct_type(&arg.ty);
    match (target_ty.clone(), resolved_arg.clone()) {
        (Type::Bytes, _) => src,
        (t, arg_ty) if t == arg_ty => src,
        (Type::Json, ty) if semantic::is_blob_like(&ty) => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::JsonDecode { dest, blob: src });
            dest
        }
        (Type::Name, ty) if semantic::is_blob_like(&ty) => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NameDecode { dest, blob: src });
            dest
        }
        (_, Type::String) => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::PointerFromString { dest, kind, src });
            dest
        }
        (_, ty) if semantic::is_blob_like(&ty) => emit_pointer_from_norito(ctx, src, kind),
        _ => src,
    }
}
fn lower_transfer_batch_call(
    ctx: &mut LowerCtx,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    // Evaluate the complete list (including every literal element) before the
    // host begins buffering this batch. The bounded list ABI supplies its active length.
    let transfers = lower_expr(ctx, &args[0], vars);
    let Type::List(element, _) = semantic::resolve_struct_type(&args[0].ty) else {
        ctx.record_error("internal error: transfer_batch lost its bounded list type".into());
        return emit_i64_const(ctx, 0);
    };
    let length = emit_load64_imm(ctx, transfers, 0);
    let index = emit_i64_const(ctx, 0);
    let one = emit_i64_const(ctx, 1);
    let header = ctx.new_label();
    let body = ctx.new_label();
    let close = ctx.new_label();
    let end = ctx.new_label();
    let open = ctx.new_label();
    let nonempty = emit_binary(ctx, BinaryOp::Lt, index, length);
    ctx.finish_current(Terminator::Branch {
        cond: nonempty,
        then_bb: open,
        else_bb: end,
    });
    ctx.start_block(open);
    ctx.current_instr(Instr::TransferBatchBegin);
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(header);
    let has_entry = emit_binary(ctx, BinaryOp::Lt, index, length);
    ctx.finish_current(Terminator::Branch {
        cond: has_entry,
        then_bb: body,
        else_bb: close,
    });
    ctx.start_block(body);
    let tuple = load_list_element(ctx, transfers, index, &element);
    let from = emit_tuple_get(ctx, tuple, 0);
    let to = emit_tuple_get(ctx, tuple, 1);
    let asset = emit_tuple_get(ctx, tuple, 2);
    let amount = emit_tuple_get(ctx, tuple, 3);
    ctx.current_instr(Instr::TransferBatchAsset {
        from,
        to,
        asset,
        amount,
    });
    let next = emit_binary(ctx, BinaryOp::Add, index, one);
    emit_copy(ctx, index, next);
    ctx.finish_current(Terminator::Jump(header));
    ctx.start_block(close);
    ctx.current_instr(Instr::TransferBatchEnd);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    emit_i64_const(ctx, 0)
}

/// Lower the absent-key fallback of `map.get_or_insert(key, default)`: return
/// the stored value, or evaluate `default` only when the key is absent, write
/// it, and return it.
fn lower_map_fallback(
    ctx: &mut LowerCtx,
    map_expr: &TypedExpr,
    key_expr: &TypedExpr,
    default_expr: &TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let key = lower_expr(ctx, key_expr, vars);
    if let Some(base) = state_map_base_name(map_expr)
        && let Some(spec) = ctx.state_map_configs.get(&base).cloned()
        && let Some(key_type) = state_map_key_type(&spec.key)
    {
        let path = build_state_map_path(ctx, &base, key, &key_type);
        let blob = emit_state_get(ctx, path);
        let zero = emit_i64_const(ctx, 0);
        let result_words = runtime_value_word_types(&spec.value)
            .into_iter()
            .map(|_| ctx.new_temp())
            .collect::<Vec<_>>();
        let present = emit_binary(ctx, BinaryOp::Ne, blob, zero);
        let present_block = ctx.new_label();
        let default_block = ctx.new_label();
        let end_block = ctx.new_label();
        ctx.finish_current(Terminator::Branch {
            cond: present,
            then_bb: present_block,
            else_bb: default_block,
        });

        ctx.start_block(present_block);
        let existing = decode_state_map_value_blob(ctx, blob, &spec.value)
            .expect("durable map value should decode");
        copy_runtime_value_words(ctx, existing, &spec.value, &result_words);
        ctx.finish_current(Terminator::Jump(end_block));

        ctx.start_block(default_block);
        let default = lower_expr(ctx, default_expr, vars);
        let _ = lower_state_map_set_value(ctx, &base, key, &spec.key, &spec.value, default);
        copy_runtime_value_words(ctx, default, &spec.value, &result_words);
        ctx.finish_current(Terminator::Jump(end_block));

        ctx.start_block(end_block);
        return rebuild_runtime_value(ctx, &spec.value, &result_words);
    }

    let map = lower_expr(ctx, map_expr, vars);
    let stored_key = ctx.new_temp();
    let stored_value = ctx.new_temp();
    ctx.current_instr(Instr::MapLoadPair {
        dest_key: stored_key,
        dest_val: stored_value,
        map,
        offset: 0,
    });
    let zero = emit_i64_const(ctx, 0);
    let result = ctx.new_temp();
    let present = lower_map_key_eq(ctx, &key_expr.ty, stored_key, key);
    let present_block = ctx.new_label();
    let default_block = ctx.new_label();
    let end_block = ctx.new_label();
    ctx.finish_current(Terminator::Branch {
        cond: present,
        then_bb: present_block,
        else_bb: default_block,
    });

    ctx.start_block(present_block);
    ctx.current_instr(Instr::Binary {
        dest: result,
        op: BinaryOp::Add,
        left: stored_value,
        right: zero,
    });
    ctx.finish_current(Terminator::Jump(end_block));

    ctx.start_block(default_block);
    let default = lower_expr(ctx, default_expr, vars);
    ctx.current_instr(Instr::MapSet {
        map,
        key,
        value: default,
    });
    ctx.current_instr(Instr::Binary {
        dest: result,
        op: BinaryOp::Add,
        left: default,
        right: zero,
    });
    ctx.finish_current(Terminator::Jump(end_block));

    ctx.start_block(end_block);
    result
}

fn lower_take2_pair(
    ctx: &mut LowerCtx,
    args: &[TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> (Temp, Temp) {
    let base = lower_expr(ctx, &args[0], vars);
    let start = lower_expr_as_u64(ctx, &args[1], vars);
    let which = lower_expr_as_u64(ctx, &args[2], vars);
    let one = emit_i64_const(ctx, 1);
    let masked = emit_binary(ctx, BinaryOp::And, which, one);
    let index = emit_binary(ctx, BinaryOp::Add, start, masked);
    let sixteen = emit_i64_const(ctx, 16);
    let bytes = emit_binary(ctx, BinaryOp::Mul, index, sixteen);
    let address = emit_binary(ctx, BinaryOp::Add, base, bytes);
    (
        emit_load64_imm(ctx, address, 0),
        emit_load64_imm(ctx, address, 8),
    )
}
fn lower_surface_builtin_call(
    ctx: &mut LowerCtx,
    builtin: Builtin,
    args: &[semantic::TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    match builtin {
        Builtin::PointerConstructor(constructor) => {
            lower_pointer_constructor_call(ctx, constructor, args, vars)
        }
        Builtin::NumericToIntDirect
        | Builtin::NumericAddDirect
        | Builtin::NumericSubDirect
        | Builtin::NumericMulDirect
        | Builtin::NumericDivDirect
        | Builtin::NumericRemDirect
        | Builtin::NumericNegDirect
        | Builtin::NumericEqDirect
        | Builtin::NumericNeDirect
        | Builtin::NumericLtDirect
        | Builtin::NumericLeDirect
        | Builtin::NumericGtDirect
        | Builtin::NumericGeDirect
        | Builtin::SetAssetTransferDailyLimit
        | Builtin::SetAssetHoldingLimit
        | Builtin::ContractSubject => lower_direct_helper_call(ctx, builtin, args, vars),
        Builtin::AccountRecoveryPropose
        | Builtin::AccountRecoveryApprove
        | Builtin::AccountRecoveryCancel
        | Builtin::AccountRecoveryFinalize => {
            let generation_index = if builtin == Builtin::AccountRecoveryPropose {
                2
            } else {
                1
            };
            let mut lowered_args = Vec::with_capacity(args.len());
            for (index, argument) in args.iter().enumerate() {
                lowered_args.push(if index == generation_index {
                    lower_expr_as_u64(ctx, argument, vars)
                } else {
                    lower_expr(ctx, argument, vars)
                });
            }
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::DirectHelperSyscall {
                dest,
                syscall: direct_builtin_syscall(builtin),
                args: lowered_args,
            });
            dest
        }
        Builtin::SetAssetTransferAvailability => {
            let account = lower_expr(ctx, &args[0], vars);
            let asset_definition = lower_expr(ctx, &args[1], vars);
            let expected_revision = lower_expr_as_u64(ctx, &args[2], vars);
            let incoming = lower_expr(ctx, &args[3], vars);
            let outgoing = lower_expr(ctx, &args[4], vars);
            let reason = lower_expr(ctx, &args[5], vars);
            // ABI v1 exposes only r10..r14. Keep the source-level API explicit while
            // packing the two booleans into one physical flags word.
            let two = emit_i64_const(ctx, 2);
            let outgoing_bit = emit_binary(ctx, BinaryOp::Mul, outgoing, two);
            let availability_flags = emit_binary(ctx, BinaryOp::Add, incoming, outgoing_bit);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::DirectHelperSyscall {
                dest,
                syscall: ivm_abi::syscalls::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
                args: vec![
                    account,
                    asset_definition,
                    expected_revision,
                    availability_flags,
                    reason,
                ],
            });
            dest
        }
        Builtin::SchemaEncode => {
            let schema = lower_expr(ctx, &args[0], vars);
            let json = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::SchemaEncode { dest, schema, json });
            dest
        }
        Builtin::SchemaDecode => {
            let schema = lower_expr(ctx, &args[0], vars);
            let blob = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::SchemaDecode { dest, schema, blob });
            dest
        }
        Builtin::SchemaInfo => {
            let schema = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::SchemaInfo { dest, schema });
            dest
        }
        Builtin::NumericNeg => {
            let value = lower_expr(ctx, &args[0], vars);
            if matches!(
                wide_numeric_kind_for_type(&args[0].ty),
                Some(WideNumericKind::Quantity)
            ) {
                ctx.record_error("quantity is non-negative and cannot be negated".into());
                let dest = ctx.new_temp();
                ctx.current_instr(Instr::Const { dest, value: 0 });
                return dest;
            }
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NumericNeg {
                dest,
                value,
                kind: wide_numeric_kind_for_type(&args[0].ty)
                    .expect("numeric negation operand has an ABI kind"),
            });
            dest
        }
        Builtin::JsonObject => {
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonObject { dest: d });
            d
        }
        Builtin::JsonSetInt => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let v = lower_expr_as_i64(ctx, &args[2], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonSetInt {
                dest: d,
                json: j,
                key: k,
                value: v,
            });
            d
        }
        Builtin::JsonSetAccountId => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let v = lower_expr(ctx, &args[2], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonSetAccountId {
                dest: d,
                json: j,
                key: k,
                value: v,
            });
            d
        }
        Builtin::EncodeJson => {
            let json = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::JsonEncode { dest, json });
            dest
        }
        Builtin::DecodeJson => {
            let blob = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::JsonDecode { dest, blob });
            dest
        }
        builtin @ (Builtin::GetInt | Builtin::GetDecimal | Builtin::GetQuantity) => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetNumeric {
                dest: d,
                json: j,
                key: k,
                kind: match builtin {
                    Builtin::GetInt => WideNumericKind::Int,
                    Builtin::GetDecimal => WideNumericKind::Decimal,
                    Builtin::GetQuantity => WideNumericKind::Quantity,
                    _ => unreachable!("matched typed numeric JSON getter"),
                },
            });
            d
        }
        Builtin::GetJson => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetJson {
                dest: d,
                json: j,
                key: k,
            });
            d
        }
        Builtin::GetName => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetName {
                dest: d,
                json: j,
                key: k,
            });
            d
        }
        Builtin::GetAccountId => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetAccountId {
                dest: d,
                json: j,
                key: k,
            });
            d
        }
        Builtin::GetAssetDefinitionId => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetAssetDefinitionId {
                dest: d,
                json: j,
                key: k,
            });
            d
        }
        Builtin::GetNftId => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetNftId {
                dest: d,
                json: j,
                key: k,
            });
            d
        }
        Builtin::GetBytesHex => {
            let j = lower_expr(ctx, &args[0], vars);
            let k = lower_expr(ctx, &args[1], vars);
            let d = ctx.new_temp();
            ctx.current_instr(Instr::JsonGetBlobHex {
                dest: d,
                json: j,
                key: k,
            });
            d
        }
        Builtin::GetString | Builtin::GetBool => {
            let json = lower_expr(ctx, &args[0], vars);
            let key = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(if builtin == Builtin::GetString {
                Instr::JsonGetString { dest, json, key }
            } else {
                Instr::JsonGetBool { dest, json, key }
            });
            dest
        }
        Builtin::TriggerEvent => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::GetTriggerEvent { dest });
            dest
        }
        Builtin::Authority => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::GetAuthority { dest });
            dest
        }
        Builtin::SysvarAuthority => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::SysvarAuthority { dest });
            dest
        }
        Builtin::TransactionTimeMs => {
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::CurrentTimeMs { dest: scalar });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::BlockHeight => {
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::BlockHeight { dest: scalar });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::BlockTimeMs => {
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::BlockTimeMs { dest: scalar });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::ChainId => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ChainId { dest });
            dest
        }
        Builtin::ContractAddress => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ContractAddress { dest });
            dest
        }
        Builtin::Entrypoint => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::Entrypoint { dest });
            dest
        }
        Builtin::Path => {
            let base = lower_expr(ctx, &args[0], vars);
            let key = lower_expr(ctx, &args[1], vars);
            let key_blob = encode_aggregate_state_value(ctx, key, &args[1].ty)
                .expect("validated canonical StateMap key");
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::PathMapKeyNorito {
                dest,
                base,
                key_blob,
            });
            dest
        }
        Builtin::NameDecode => {
            let blob = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NameDecode { dest, blob });
            dest
        }
        Builtin::TlvEq => {
            let left = lower_expr(ctx, &args[0], vars);
            let right = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::PointerEq { dest, left, right });
            dest
        }
        Builtin::TlvLen | Builtin::BytesLen | Builtin::StringLen => {
            let value = lower_expr(ctx, &args[0], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::TlvLen {
                dest: scalar,
                value,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::StringAsBytes => lower_expr(ctx, &args[0], vars),
        Builtin::BytesConcat | Builtin::StringConcat => {
            lower_direct_helper_call(ctx, builtin, args, vars)
        }
        Builtin::StringFromBytes => {
            let pointer = lower_direct_helper_call(ctx, builtin, args, vars);
            lower_nullable_pointer(ctx, pointer, &Type::String)
        }
        Builtin::ValueEncode | Builtin::StringFrom => {
            let value = lower_expr(ctx, &args[0], vars);
            let schema = entrypoint_value_type(builtin.source_name(), &args[0].ty)
                .expect("validated public utility operand");
            let encoded = ivm_abi::codec::encode_canonical_norito(&schema)
                .expect("canonical utility value schema");
            let schema = emit_data_ref(
                ctx,
                DataRefKind::NoritoBytes,
                format!("0x{}", hex::encode(encoded)),
            );
            let mut words = Vec::new();
            collect_function_value_words(ctx, value, &args[0].ty, &mut words);
            let count = emit_i64_const(ctx, words.len() as i64);
            let table = materialize_value_word_table(ctx, &words);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::DirectHelperSyscall {
                dest,
                syscall: direct_builtin_syscall(builtin),
                args: vec![schema, table, count],
            });
            dest
        }
        Builtin::PointerToNorito => {
            let value = lower_expr(ctx, &args[0], vars);
            emit_pointer_to_norito(ctx, value)
        }
        Builtin::NumericToInt => {
            let value = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NumericConvert {
                dest,
                value,
                source: wide_numeric_kind_for_type(&args[0].ty)
                    .expect("numeric conversion operand has an ABI kind"),
                destination: WideNumericKind::Int,
            });
            dest
        }
        builtin @ (Builtin::NumericAdd
        | Builtin::NumericSub
        | Builtin::NumericMul
        | Builtin::NumericDiv
        | Builtin::NumericRem) => {
            let left = lower_expr(ctx, &args[0], vars);
            let right = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NumericBinary {
                dest,
                op: numeric_binary_builtin_op(builtin).expect("numeric binary builtin op"),
                left,
                right,
                left_kind: wide_numeric_kind_for_type(&args[0].ty)
                    .expect("numeric binary left operand has an ABI kind"),
                right_kind: wide_numeric_kind_for_type(&args[1].ty)
                    .expect("numeric binary right operand has an ABI kind"),
                result_kind: wide_numeric_kind_for_type(&args[0].ty)
                    .expect("numeric binary result has an ABI kind"),
            });
            dest
        }
        builtin @ (Builtin::NumericEq
        | Builtin::NumericNe
        | Builtin::NumericLt
        | Builtin::NumericLe
        | Builtin::NumericGt
        | Builtin::NumericGe) => {
            let left = lower_expr(ctx, &args[0], vars);
            let right = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::NumericCompare {
                dest,
                op: numeric_compare_builtin_op(builtin).expect("numeric compare builtin op"),
                left,
                right,
                kind: wide_numeric_kind_for_type(&args[0].ty)
                    .expect("numeric comparison operand has a nominal ABI kind"),
            });
            dest
        }
        Builtin::WrappingNeg => {
            let operand = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::WrappingNeg { dest, operand });
            dest
        }
        builtin @ (Builtin::WrappingAdd | Builtin::WrappingSub | Builtin::WrappingMul) => {
            let left = lower_expr(ctx, &args[0], vars);
            let right = lower_expr(ctx, &args[1], vars);
            let op = match builtin {
                Builtin::WrappingAdd => BinaryOp::Add,
                Builtin::WrappingSub => BinaryOp::Sub,
                Builtin::WrappingMul => BinaryOp::Mul,
                _ => unreachable!(),
            };
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::WrappingBinary {
                dest,
                op,
                left,
                right,
            });
            dest
        }
        Builtin::Min | Builtin::Max | Builtin::Abs => {
            lower_numeric_selection(ctx, builtin, args, vars)
        }
        builtin @ (Builtin::Isqrt | Builtin::DivCeil | Builtin::Gcd | Builtin::Mean) => {
            lower_direct_helper_call(ctx, builtin, args, vars)
        }
        Builtin::Poseidon2 => {
            let a = lower_expr_as_u64(ctx, &args[0], vars);
            let b = lower_expr_as_u64(ctx, &args[1], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::Poseidon2 { dest: scalar, a, b });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::Poseidon6 => {
            let mut lowered_args = [Temp(0); 6];
            for (index, arg) in args.iter().enumerate() {
                lowered_args[index] = lower_expr_as_u64(ctx, arg, vars);
            }
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::Poseidon6 {
                dest: scalar,
                args: lowered_args,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::Pubkgen => {
            let src = lower_expr_as_u64(ctx, &args[0], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::Pubkgen { dest: scalar, src });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::Valcom => {
            if args
                .iter()
                .any(|arg| crate::secret::type_contains_secret(&arg.ty))
            {
                let value = lower_expr(ctx, &args[0], vars);
                let blind = lower_expr(ctx, &args[1], vars);
                let dest = ctx.new_temp();
                ctx.current_instr(Instr::PrivateNumericValcom { dest, value, blind });
                return dest;
            }
            let value = lower_expr_as_u64(ctx, &args[0], vars);
            let blind = lower_expr_as_u64(ctx, &args[1], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::Valcom {
                dest: scalar,
                value,
                blind,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::SetVl => {
            let value = lower_expr_as_u64(ctx, &args[0], vars);
            ctx.current_instr(Instr::SetVl { value });
            emit_i64_const(ctx, 0)
        }
        Builtin::StateGet => {
            let p = lower_expr(ctx, &args[0], vars);
            emit_state_get(ctx, p)
        }
        Builtin::StateSet => {
            let path = lower_expr(ctx, &args[0], vars);
            let val = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::StateSet { path, value: val });
            emit_i64_const(ctx, 0)
        }
        Builtin::StateDel => {
            let path = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::StateDel { path });
            emit_i64_const(ctx, 0)
        }
        Builtin::StateHas => {
            let path = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::StateHas { dest, path });
            dest
        }
        Builtin::StateLen => {
            let path = lower_expr(ctx, &args[0], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::StateLen { dest: scalar, path });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::StateCount => {
            let prefix = lower_expr(ctx, &args[0], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::StateCount {
                dest: scalar,
                prefix,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::QueryExecuteNorito => {
            let payload = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::QueryExecuteNorito { dest, payload });
            dest
        }
        Builtin::QueryGetAccount
        | Builtin::QueryGetAsset
        | Builtin::QueryGetAssetDefinition
        | Builtin::QueryGetDomain
        | Builtin::QueryGetNft => {
            let key = lower_expr(ctx, &args[0], vars);
            let entity = match builtin {
                Builtin::QueryGetAccount => ivm_abi::core_query::CoreQueryEntityTagV1::Account,
                Builtin::QueryGetAsset => ivm_abi::core_query::CoreQueryEntityTagV1::Asset,
                Builtin::QueryGetAssetDefinition => {
                    ivm_abi::core_query::CoreQueryEntityTagV1::AssetDefinition
                }
                Builtin::QueryGetDomain => ivm_abi::core_query::CoreQueryEntityTagV1::Domain,
                Builtin::QueryGetNft => ivm_abi::core_query::CoreQueryEntityTagV1::Nft,
                _ => unreachable!("matched only V1 core-query builtins"),
            };
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::CoreQueryGet { dest, key, entity });
            dest
        }
        Builtin::QueryPageAccounts
        | Builtin::QueryPageAssets
        | Builtin::QueryPageAssetsOf
        | Builtin::QueryPageAssetDefinitions
        | Builtin::QueryPageDomains
        | Builtin::QueryPageNfts => {
            let account =
                (builtin == Builtin::QueryPageAssetsOf).then(|| lower_expr(ctx, &args[0], vars));
            let first = usize::from(account.is_some());
            let offset = lower_expr_as_i64(ctx, &args[first], vars);
            let limit = lower_expr_as_u64(ctx, &args[first + 1], vars);
            let entity = match builtin {
                Builtin::QueryPageAccounts => ivm_abi::core_query::CoreQueryEntityTagV1::Account,
                Builtin::QueryPageAssets | Builtin::QueryPageAssetsOf => {
                    ivm_abi::core_query::CoreQueryEntityTagV1::Asset
                }
                Builtin::QueryPageAssetDefinitions => {
                    ivm_abi::core_query::CoreQueryEntityTagV1::AssetDefinition
                }
                Builtin::QueryPageDomains => ivm_abi::core_query::CoreQueryEntityTagV1::Domain,
                Builtin::QueryPageNfts => ivm_abi::core_query::CoreQueryEntityTagV1::Nft,
                _ => unreachable!("matched only V1 core-query page builtins"),
            };
            let items_dest = ctx.new_temp();
            let next_offset_dest = ctx.new_temp();
            ctx.current_instr(Instr::CoreQueryPage {
                items_dest,
                next_offset_dest,
                entity,
                account,
                offset,
                limit,
            });
            emit_tuple_pack(ctx, vec![items_dest, next_offset_dest])
        }
        Builtin::QueryGetParameter
        | Builtin::QueryGetContractManifest
        | Builtin::QueryGetContractInstance => {
            let key = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::QueryGet {
                dest,
                key,
                syscall: direct_builtin_syscall(builtin),
            });
            dest
        }
        Builtin::BuildSubmitBallotInline => {
            let election_id = lower_expr(ctx, &args[0], vars);
            let ciphertext = lower_expr(ctx, &args[1], vars);
            let nullifier = lower_expr(ctx, &args[2], vars);
            let backend = lower_expr(ctx, &args[3], vars);
            let proof = lower_expr(ctx, &args[4], vars);
            let vk = lower_expr(ctx, &args[5], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::BuildSubmitBallotInline {
                dest,
                election_id,
                ciphertext,
                nullifier,
                backend,
                proof,
                vk,
            });
            dest
        }
        Builtin::ScExecuteSubmitBallot => {
            let payload = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::VendorExecuteInstruction {
                payload,
                kind: VendorInstructionKind::SubmitBallot,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::ExecuteQuery => {
            let payload = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::VendorExecuteQuery { dest, payload });
            dest
        }
        Builtin::ResolveAccountAlias => {
            let alias = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ResolveAccountAlias { dest, alias });
            dest
        }
        Builtin::SubscriptionBill => {
            ctx.current_instr(Instr::SubscriptionBill);
            emit_i64_const(ctx, 0)
        }
        Builtin::SubscriptionRecordUsage => {
            ctx.current_instr(Instr::SubscriptionRecordUsage);
            emit_i64_const(ctx, 0)
        }
        Builtin::GetAccountBalance => {
            let account = lower_expr(ctx, &args[0], vars);
            let asset = lower_expr(ctx, &args[1], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::GetAccountBalance {
                dest,
                account,
                asset,
            });
            dest
        }
        Builtin::GetPublicInput => {
            let key = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::GetPublicInput { dest, key });
            dest
        }
        Builtin::DebugPrint => {
            let value = lower_expr_as_i64(ctx, &args[0], vars);
            ctx.current_instr(Instr::DebugPrint { value });
            emit_i64_const(ctx, 0)
        }
        Builtin::DebugLog => {
            let payload = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::DebugLog { payload });
            emit_i64_const(ctx, 0)
        }
        Builtin::Assert => {
            // Typed arguments: condition, optional message, compiler-owned assertion site.
            let (site, values) = args.split_last().expect("typed assertion site");
            let cond = lower_expr(ctx, &values[0], vars);
            let message = values.get(1).map(|message| lower_expr(ctx, message, vars));
            emit_test_assertion(ctx, cond, site, None, message, vars);
            emit_i64_const(ctx, 0)
        }
        Builtin::Require => {
            let cond = lower_expr(ctx, &args[0], vars);
            let code = lower_expr(ctx, &args[1], vars);
            let Type::ErrorEnum(error_type) = &args[1].ty else {
                unreachable!("typed nominal error")
            };
            let encoded = ivm_abi::codec::encode_canonical_norito(error_type.as_ref())
                .expect("validated nominal error schema encodes");
            let descriptor = emit_data_ref(
                ctx,
                DataRefKind::NoritoBytes,
                format!("0x{}", hex::encode(encoded)),
            );
            let reject = emit_unary(ctx, UnaryOp::Not, cond);
            ctx.current_instr(Instr::AbortIf {
                cond: reject,
                descriptor,
                code,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::Info => {
            let msg = if matches!(semantic::resolve_struct_type(&args[0].ty), Type::Int) {
                let value = lower_expr(ctx, &args[0], vars);
                let encoded = ctx.new_temp();
                ctx.current_instr(Instr::PointerToNorito {
                    dest: encoded,
                    value,
                });
                encoded
            } else {
                lower_expr(ctx, &args[0], vars)
            };
            ctx.current_instr(Instr::Info { msg });
            emit_i64_const(ctx, 0)
        }
        Builtin::AssertEq => {
            // Typed arguments: actual, expected, optional message, compiler-owned assertion site.
            let (site, values) = args.split_last().expect("typed assertion site");
            let ty = values[0].ty.clone();
            let actual = lower_expr(ctx, &values[0], vars);
            let expected = lower_expr(ctx, &values[1], vars);
            let message = values.get(2).map(|message| lower_expr(ctx, message, vars));
            let equal = emit_typed_value_eq(ctx, actual, expected, &ty);
            emit_test_assertion(
                ctx,
                equal,
                site,
                Some((actual, expected, &ty)),
                message,
                vars,
            );
            emit_i64_const(ctx, 0)
        }
        Builtin::SetAccountMetadata => {
            let account = lower_expr(ctx, &args[0], vars);
            let key = lower_expr(ctx, &args[1], vars);
            let value = lower_expr(ctx, &args[2], vars);
            ctx.current_instr(Instr::SetAccountDetail {
                account,
                key,
                value,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::MintAsset => {
            let acc = lower_expr(ctx, &args[0], vars);
            let asset = lower_expr(ctx, &args[1], vars);
            let amt = match args[2].kind() {
                semantic::ExprKind::IntLiteral(value)
                    if value.is_zero() && !semantic::is_wide_numeric_type(&args[2].ty) =>
                {
                    emit_i64_const(ctx, 0)
                }
                _ => lower_expr_as_numeric(ctx, &args[2], vars),
            };
            ctx.current_instr(Instr::MintAsset {
                account: acc,
                asset,
                amount: amt,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::BurnAsset => {
            let acc = lower_expr(ctx, &args[0], vars);
            let asset = lower_expr(ctx, &args[1], vars);
            let amt = lower_expr_as_numeric(ctx, &args[2], vars);
            ctx.current_instr(Instr::BurnAsset {
                account: acc,
                asset,
                amount: amt,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::TransferAsset => {
            let from = lower_expr(ctx, &args[0], vars);
            let to = lower_expr(ctx, &args[1], vars);
            let asset = lower_expr(ctx, &args[2], vars);
            let amt = lower_expr_as_numeric(ctx, &args[3], vars);
            // An omitted `dataspace:` is the constant zero word: the host then
            // applies the definition's global policy and rejects a
            // dataspace-restricted definition.
            let dataspace = match args.get(4) {
                Some(dataspace) => lower_expr(ctx, dataspace, vars),
                None => emit_i64_const(ctx, 0),
            };
            ctx.current_instr(Instr::TransferAsset {
                from,
                to,
                asset,
                amount: amt,
                dataspace,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::NftMintAsset => {
            let nft = lower_expr(ctx, &args[0], vars);
            let owner = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::CreateNft { nft, owner });
            emit_i64_const(ctx, 0)
        }
        Builtin::NftSetMetadata => {
            let nft = lower_expr(ctx, &args[0], vars);
            let key = lower_expr(ctx, &args[1], vars);
            let json = lower_expr(ctx, &args[2], vars);
            ctx.current_instr(Instr::SetNftData { nft, key, json });
            emit_i64_const(ctx, 0)
        }
        Builtin::NftBurnAsset => {
            let nft = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::BurnNft { nft });
            emit_i64_const(ctx, 0)
        }
        Builtin::NftTransferAsset => {
            let from = lower_expr(ctx, &args[0], vars);
            let nft = lower_expr(ctx, &args[1], vars);
            let to = lower_expr(ctx, &args[2], vars);
            ctx.current_instr(Instr::TransferNft { from, nft, to });
            emit_i64_const(ctx, 0)
        }
        Builtin::RegisterDomain => {
            let domain = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::RegisterDomain { domain });
            emit_i64_const(ctx, 0)
        }
        Builtin::UnregisterDomain => {
            let domain = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::UnregisterDomain { domain });
            emit_i64_const(ctx, 0)
        }
        Builtin::TransferDomain => {
            let domain = lower_expr(ctx, &args[1], vars);
            let to = lower_expr(ctx, &args[2], vars);
            ctx.current_instr(Instr::TransferDomain { domain, to });
            emit_i64_const(ctx, 0)
        }
        Builtin::RegisterAccount => {
            let account = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::RegisterAccount { account });
            emit_i64_const(ctx, 0)
        }
        Builtin::UnregisterAccount => {
            let account = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::UnregisterAccount { account });
            emit_i64_const(ctx, 0)
        }
        Builtin::RegisterAsset => {
            // `spec` and `mintable` were folded by semantic analysis into
            // the `ivm_registration` words every host decodes.
            let asset = lower_expr(ctx, &args[0], vars);
            let name = lower_expr(ctx, &args[1], vars);
            let spec = lower_expr_as_u64(ctx, &args[2], vars);
            let mintable = lower_expr_as_u64(ctx, &args[3], vars);
            ctx.current_instr(Instr::RegisterAsset {
                asset,
                name,
                spec,
                mintable,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::UnregisterAsset => {
            let asset = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::UnregisterAsset { asset });
            emit_i64_const(ctx, 0)
        }
        Builtin::RegisterPeer => {
            let json = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::RegisterPeer { json });
            emit_i64_const(ctx, 0)
        }
        Builtin::UnregisterPeer => {
            let json = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::UnregisterPeer { json });
            emit_i64_const(ctx, 0)
        }
        Builtin::RegisterTrigger => {
            let json = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::CreateTrigger { json });
            emit_i64_const(ctx, 0)
        }
        Builtin::UnregisterTrigger => {
            let name = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::RemoveTrigger { name });
            emit_i64_const(ctx, 0)
        }
        Builtin::SetTriggerEnabled => {
            let name = lower_expr(ctx, &args[0], vars);
            let enabled = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::SetTriggerEnabled { name, enabled });
            emit_i64_const(ctx, 0)
        }
        Builtin::RegisterRole => {
            let name = lower_expr(ctx, &args[0], vars);
            let json = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::CreateRole { name, json });
            emit_i64_const(ctx, 0)
        }
        Builtin::UnregisterRole => {
            let name = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::DeleteRole { name });
            emit_i64_const(ctx, 0)
        }
        Builtin::GrantRole => {
            let account = lower_expr(ctx, &args[0], vars);
            let name = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::GrantRole { account, name });
            emit_i64_const(ctx, 0)
        }
        Builtin::RevokeRole => {
            let account = lower_expr(ctx, &args[0], vars);
            let name = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::RevokeRole { account, name });
            emit_i64_const(ctx, 0)
        }
        Builtin::GrantPermission => {
            let account = lower_expr(ctx, &args[0], vars);
            let token = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::GrantPermission { account, token });
            emit_i64_const(ctx, 0)
        }
        Builtin::RevokePermission => {
            let account = lower_expr(ctx, &args[0], vars);
            let token = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::RevokePermission { account, token });
            emit_i64_const(ctx, 0)
        }
        Builtin::GrantContractPermission => {
            let account = lower_expr(ctx, &args[0], vars);
            let permission = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::GrantContractPermission {
                account,
                permission,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::RevokeContractPermission => {
            let account = lower_expr(ctx, &args[0], vars);
            let permission = lower_expr(ctx, &args[1], vars);
            ctx.current_instr(Instr::RevokeContractPermission {
                account,
                permission,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowOpenOffer => {
            let escrow = lower_expr(ctx, &args[0], vars);
            let asset = lower_expr(ctx, &args[1], vars);
            let amount = lower_expr_as_numeric(ctx, &args[2], vars);
            let evidence_hashes = args.get(3).map(|arg| lower_expr(ctx, arg, vars));
            ctx.current_instr(Instr::EscrowOpenOffer {
                escrow,
                asset,
                amount,
                evidence_hashes,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowAccept => {
            let escrow = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::EscrowAccept { escrow });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowMarkPaymentSent => {
            let escrow = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::EscrowMarkPaymentSent { escrow });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowRelease => {
            let escrow = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::EscrowRelease { escrow });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowCancel => {
            let escrow = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::EscrowCancel { escrow });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowOpenDispute => {
            let escrow = lower_expr(ctx, &args[0], vars);
            let evidence_hashes = args.get(1).map(|arg| lower_expr(ctx, arg, vars));
            ctx.current_instr(Instr::EscrowOpenDispute {
                escrow,
                evidence_hashes,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::EscrowResolveDispute => {
            let escrow = lower_expr(ctx, &args[0], vars);
            let buyer_amount = lower_expr_as_numeric(ctx, &args[1], vars);
            let seller_amount = lower_expr_as_numeric(ctx, &args[2], vars);
            let evidence_hashes = args.get(3).map(|arg| lower_expr(ctx, arg, vars));
            ctx.current_instr(Instr::EscrowResolveDispute {
                escrow,
                buyer_amount,
                seller_amount,
                evidence_hashes,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::Alloc => {
            let bytes = lower_expr_as_u64(ctx, &args[0], vars);
            let scalar = emit_alloc(ctx, bytes);
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::GetPrivateInput => {
            let index = lower_expr_as_u64(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            let kind = match semantic::resolve_struct_type(result_ty) {
                Type::Secret(payload) => match payload.as_ref() {
                    Type::Int => ivm_abi::private_input::PrivateInputKindV1::Int,
                    Type::Decimal => ivm_abi::private_input::PrivateInputKindV1::Decimal,
                    Type::Quantity => ivm_abi::private_input::PrivateInputKindV1::Quantity,
                    other => panic!("unsupported typed private-input payload: {other:?}"),
                },
                other => panic!("private-input call lowered with non-secret type: {other:?}"),
            };
            ctx.current_instr(Instr::GetPrivateInput { dest, index, kind });
            dest
        }
        Builtin::CommitOutput => {
            ctx.current_instr(Instr::CommitOutput);
            emit_i64_const(ctx, 0)
        }
        Builtin::CreateNftsForAllUsers => {
            ctx.current_instr(Instr::CreateNftsForAllUsers);
            emit_i64_const(ctx, 0)
        }
        Builtin::SetExecutionDepth => {
            let value = lower_expr_as_u64(ctx, &args[0], vars);
            ctx.current_instr(Instr::SetExecutionDepth { value });
            emit_i64_const(ctx, 0)
        }
        Builtin::TransferBatch => lower_transfer_batch_call(ctx, args, vars),
        Builtin::AxtBegin => {
            let desc = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::AxtBegin { descriptor: desc });
            emit_i64_const(ctx, 0)
        }
        Builtin::AxtTouch => {
            let dsid = lower_expr(ctx, &args[0], vars);
            let manifest = args.get(1).map(|m| lower_expr(ctx, m, vars));
            ctx.current_instr(Instr::AxtTouch { dsid, manifest });
            emit_i64_const(ctx, 0)
        }
        Builtin::StageAnchoredSpend => {
            let spend = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::StageAnchoredSpend { spend });
            emit_i64_const(ctx, 0)
        }
        Builtin::VerifyDsProof => {
            let dsid = lower_expr(ctx, &args[0], vars);
            let proof = args.get(1).map(|p| lower_expr(ctx, p, vars));
            ctx.current_instr(Instr::VerifyDsProof { dsid, proof });
            emit_i64_const(ctx, 0)
        }
        Builtin::AxtCommit => {
            ctx.current_instr(Instr::AxtCommit);
            emit_i64_const(ctx, 0)
        }
        Builtin::DeactivateContractInstance
        | Builtin::RemoveSmartContractBytes
        | Builtin::RegisterSmartContractCode
        | Builtin::RegisterSmartContractBytes
        | Builtin::ActivateContractInstance => {
            let payload = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::SmartContractLifecycle {
                payload,
                syscall: direct_builtin_syscall(builtin),
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::ZkRootsGet => {
            let payload = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ZkRootsGet { dest, payload });
            dest
        }
        Builtin::ZkVoteGetTally => {
            let payload = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ZkVoteGetTally { dest, payload });
            dest
        }
        builtin @ (Builtin::ZkVerifyBatch
        | Builtin::ZkVoteVerifyBallot
        | Builtin::ZkVoteVerifyTally) => {
            let payload = lower_expr(ctx, &args[0], vars);
            ctx.current_instr(Instr::ZkVerify {
                number: direct_builtin_syscall(builtin),
                payload,
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::VrfEpochSeed => {
            let epoch = lower_expr_as_u64(ctx, &args[0], vars);
            let pointer = ctx.new_temp();
            ctx.current_instr(Instr::VrfEpochSeed {
                dest: pointer,
                epoch,
            });
            lower_nullable_pointer(ctx, pointer, &Type::Bytes)
        }
        Builtin::VrfVerify => {
            let request = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::VrfVerify { dest, request });
            dest
        }
        Builtin::VrfVerifyBatch => {
            let batch = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::VrfVerifyBatch { dest, batch });
            dest
        }
        Builtin::Sm3Hash
        | Builtin::Sha256Hash
        | Builtin::Sha3Hash
        | Builtin::Blake2b256Hash
        | Builtin::Keccak256Hash
        | Builtin::IrohaHash => lower_hash_builtin_call(ctx, builtin, args, vars),
        Builtin::Sm2Verify | Builtin::VerifySignature => {
            lower_signature_builtin_call(ctx, builtin, args, vars)
        }
        Builtin::Sm4GcmSeal | Builtin::Sm4GcmOpen | Builtin::Sm4CcmSeal | Builtin::Sm4CcmOpen => {
            lower_sm4_builtin_call(ctx, builtin, args, vars)
        }
        Builtin::ExecutionSummary => {
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::ExecutionSummary { dest });
            dest
        }
        Builtin::GrowHeap => {
            let bytes = lower_expr_as_u64(ctx, &args[0], vars);
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::GrowHeap {
                dest: scalar,
                bytes,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::GetMerklePath => {
            let address = lower_expr_as_u64(ctx, &args[0], vars);
            let output = lower_expr_as_u64(ctx, &args[1], vars);
            let root_output = args.get(2).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::GetMerklePath {
                dest: scalar,
                address,
                output,
                root_output,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::GetMerkleCompact => {
            let address = lower_expr_as_u64(ctx, &args[0], vars);
            let output = lower_expr_as_u64(ctx, &args[1], vars);
            let max_depth = args.get(2).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            let root_output = args.get(3).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::GetMerkleCompact {
                dest: scalar,
                address,
                output,
                max_depth,
                root_output,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::GetRegisterMerkleCompact => {
            let register_index = lower_expr_as_u64(ctx, &args[0], vars);
            let output = lower_expr_as_u64(ctx, &args[1], vars);
            let max_depth = args.get(2).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            let root_output = args.get(3).map(|arg| lower_expr_as_u64(ctx, arg, vars));
            let scalar = ctx.new_temp();
            ctx.current_instr(Instr::GetRegisterMerkleCompact {
                dest: scalar,
                register_index,
                output,
                max_depth,
                root_output,
            });
            emit_int_from_u64(ctx, scalar)
        }
        Builtin::VerifyProof => {
            let payload = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::VerifyProof { dest, payload });
            dest
        }
        Builtin::SoracloudReadCommittedState
        | Builtin::SoracloudEmitStateMutation
        | Builtin::SoracloudEmitMailboxMessage
        | Builtin::SoracloudAppendJournal
        | Builtin::SoracloudPublishCheckpoint
        | Builtin::SoracloudReadConfig
        | Builtin::SoracloudReadSecretEnvelope => {
            let request = lower_expr(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::SoracloudHostCall {
                dest,
                request,
                syscall: direct_builtin_syscall(builtin),
            });
            dest
        }
        Builtin::AddSignatory | Builtin::RemoveSignatory => {
            let account = lower_expr(ctx, &args[0], vars);
            let signatory = lower_expr(ctx, &args[1], vars);
            if builtin == Builtin::AddSignatory {
                ctx.current_instr(Instr::AddSignatory { account, signatory });
            } else {
                ctx.current_instr(Instr::RemoveSignatory { account, signatory });
            }
            emit_i64_const(ctx, 0)
        }
        Builtin::SetAccountQuorum => {
            let account = lower_expr(ctx, &args[0], vars);
            let quorum = lower_expr_as_u64(ctx, &args[1], vars);
            ctx.current_instr(Instr::SetAccountQuorum { account, quorum });
            emit_i64_const(ctx, 0)
        }
        Builtin::Contains => {
            let mexpr = &args[0];
            let kexpr = &args[1];
            let key_tmp = lower_expr(ctx, kexpr, vars);
            if let Some(bn) = state_map_base_name(mexpr)
                && let Some(spec) = ctx.state_map_configs.get(&bn).cloned()
                && let Some(key_type) = state_map_key_type(&spec.key)
            {
                let t_path = build_state_map_path(ctx, &bn, key_tmp, &key_type);
                let t_blob = emit_state_get(ctx, t_path);
                let zero = emit_i64_const(ctx, 0);
                let out = emit_binary(ctx, BinaryOp::Ne, t_blob, zero);
                return out;
            }
            let m = lower_expr(ctx, mexpr, vars);
            let sk = ctx.new_temp();
            let dummy_v = ctx.new_temp();
            ctx.current_instr(Instr::MapLoadPair {
                dest_key: sk,
                dest_val: dummy_v,
                map: m,
                offset: 0,
            });
            lower_map_key_eq(ctx, &kexpr.ty, sk, key_tmp)
        }
        Builtin::GetOrInsert => lower_map_fallback(ctx, &args[0], &args[1], &args[2], vars),
        Builtin::StateMapRemove => lower_state_map_remove_option(ctx, args, vars),
        Builtin::KeysTake2 | Builtin::ValuesTake2 => {
            let (key, value) = lower_take2_pair(ctx, args, vars);
            if builtin == Builtin::KeysTake2 {
                key
            } else {
                value
            }
        }
        Builtin::KeysValuesTake2 => {
            let (key, value) = lower_take2_pair(ctx, args, vars);
            emit_tuple_pack(ctx, vec![key, value])
        }
        Builtin::TestSetBlockHeight
        | Builtin::TestAdvanceBlocks
        | Builtin::TestSetTransactionTimeMs => {
            // Host-private test syscall with one unsigned scalar operand; a negative or
            // oversized int traps in the checked conversion before the host is reached.
            let value = lower_expr_as_u64(ctx, &args[0], vars);
            let dest = ctx.new_temp();
            ctx.current_instr(Instr::DirectHelperSyscall {
                dest,
                syscall: builtin.operation_syscalls()[0],
                args: vec![value],
            });
            emit_i64_const(ctx, 0)
        }
        Builtin::TestInvokeEntrypoint
        | Builtin::TestInvokeEntrypointAs
        | Builtin::TestExpectRejectAs
        | Builtin::TestExpectAnyRejectAs
        | Builtin::TestActorAccount
        | Builtin::TestActorPublicKey
        | Builtin::TestActorSign => {
            unreachable!("test helpers use their dedicated lowering paths")
        }
        Builtin::NumericSpecUnconstrained
        | Builtin::NumericSpecInteger
        | Builtin::NumericSpecFractional
        | Builtin::MintableInfinitely
        | Builtin::MintableOnce
        | Builtin::MintableNot
        | Builtin::MintableLimited
        | Builtin::SignatureSchemeEd25519
        | Builtin::SignatureSchemeSecp256k1
        | Builtin::SignatureSchemeMlDsa => {
            ctx.record_error(format!(
                "`{}` is a compile-time argument value and has no runtime lowering",
                builtin.source_name()
            ));
            emit_i64_const(ctx, 0)
        }
    }
}
/// Return whether a named argument must be captured at its source position.
///
/// Literal leaves are total and independent of mutable compiler state, so a builtin may continue to
/// consume them directly (and, for literal-only ABI fields, entirely at compile time). Every other
/// value is captured exactly once before ABI-slot permutation. `StateMap` handles are declarations,
/// not runtime values, and their lowering is performed by the callee ABI helper.
fn named_argument_requires_capture(argument: &TypedExpr) -> bool {
    if matches!(
        semantic::resolve_struct_type(&argument.ty),
        Type::StateMap(_, _)
    ) {
        return false;
    }
    !matches!(
        argument.kind(),
        semantic::ExprKind::VariantCode(_)
            | semantic::ExprKind::IntLiteral(_)
            | semantic::ExprKind::DecimalLiteral { .. }
            | semantic::ExprKind::Bool(_)
            | semantic::ExprKind::String(_)
            | semantic::ExprKind::Bytes(_)
    )
}
/// Lower a resolved user function directly through its declared call ABI.
fn lower_user_call(
    ctx: &mut LowerCtx,
    name: &str,
    args: &[TypedExpr],
    result_ty: &semantic::Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    // User-defined function call: pass args; capture result(s) if any.
    let mut arg_tmps = Vec::new();
    let signature = ctx.function_param_specs.get(name).cloned();
    for (idx, a) in args.iter().enumerate() {
        if signature
            .as_ref()
            .and_then(|params| params.get(idx))
            .is_some_and(|param| param.is_state)
        {
            let param = signature
                .as_ref()
                .and_then(|params| params.get(idx))
                .expect("checked state parameter");
            arg_tmps.extend(lower_state_handle_args(ctx, a, &param.ty, vars));
        } else if let Some(param) = signature.as_ref().and_then(|params| params.get(idx))
            && function_value_word_types(&param.ty).is_some()
        {
            let value = lower_expr(ctx, a, vars);
            collect_function_value_words(ctx, value, &param.ty, &mut arg_tmps);
        } else {
            arg_tmps.push(lower_expr(ctx, a, vars));
        }
    }
    match result_ty {
        semantic::Type::Unit => {
            ctx.current_instr(Instr::Call {
                callee: ctx.call_target(name),
                args: arg_tmps,
                dest: None,
            });
            emit_i64_const(ctx, 0)
        }
        aggregate if function_value_word_types(aggregate).is_some() => {
            let word_types =
                function_value_word_types(aggregate).expect("aggregate return word types checked");
            // Multi-return: load the flattened ABI words from the result table, then
            // rebuild the compiler-only aggregate shape.
            let mut words = Vec::with_capacity(word_types.len());
            for _ in word_types {
                words.push(ctx.new_temp());
            }
            ctx.current_instr(Instr::CallMulti {
                callee: ctx.call_target(name),
                args: arg_tmps,
                dests: words.clone(),
            });
            let mut index = 0_usize;
            let value = rebuild_function_value_from_words(ctx, aggregate, &words, &mut index)
                .expect("validated aggregate return must rebuild from ABI words");
            debug_assert_eq!(index, words.len());
            value
        }
        _ => {
            let d = ctx.new_temp();
            ctx.current_instr(Instr::Call {
                callee: ctx.call_target(name),
                args: arg_tmps,
                dest: Some(d),
            });
            d
        }
    }
}
/// Lower a named call by capturing observable argument evaluations in source
/// order and then reusing their temporary identities in declaration/ABI order.
///
/// The cache is compiler-only: it emits no copies, tuple shuffles, or heap
/// allocations. Literal-only operands remain available to builtin lowering so
/// compile-time ABI fields retain the exact code generated by positional calls.
fn lower_named_call(
    ctx: &mut LowerCtx,
    result_ty: &Type,
    target: &semantic::CallTarget,
    args: &[TypedExpr],
    evaluation_order: &[usize],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    if target.is_lazy_sum_error() {
        if evaluation_order != [0, 1] {
            ctx.record_error(format!(
                "internal error: lazy sum method `{target}` has an invalid argument order"
            ));
        }
        return lower_sum_error_bridge(
            ctx,
            target.intrinsic().expect("lazy intrinsic"),
            args,
            result_ty,
            vars,
        );
    }
    let mut seen = vec![false; args.len()];
    let mut captured = vec![None; args.len()];
    for &index in evaluation_order {
        if index >= args.len() || seen[index] {
            ctx.record_error(format!(
                "internal error: named call `{target}` has an invalid source evaluation order"
            ));
            continue;
        }
        seen[index] = true;
        if named_argument_requires_capture(&args[index]) {
            captured[index] = Some(lower_expr(ctx, &args[index], vars));
        }
    }
    for (index, was_seen) in seen.iter().copied().enumerate() {
        if !was_seen {
            ctx.record_error(format!(
                "internal error: named call `{target}` omits ABI argument slot {index} from its source evaluation order"
            ));
            if named_argument_requires_capture(&args[index]) {
                captured[index] = Some(lower_expr(ctx, &args[index], vars));
            }
        }
    }
    // Re-enter the ordinary call lowering path with the validated ABI-ordered
    // expressions. The Vec allocation belongs to the compiler only; its
    // backing storage stays stable while the scoped pointer-to-temp cache is
    // active.
    let positional = TypedExpr {
        expr: semantic::ExprKind::Call {
            target: target.clone(),
            args: args.to_vec(),
        },
        ty: result_ty.clone(),
    };
    let positional_args = match positional.kind() {
        semantic::ExprKind::Call { args, .. } => args,
        _ => unreachable!("constructed a positional call"),
    };
    let scope = captured
        .into_iter()
        .enumerate()
        .filter_map(|(index, temp)| {
            temp.map(|temp| (std::ptr::from_ref(&positional_args[index]), temp))
        })
        .collect();
    ctx.prelowered_argument_scopes.push(scope);
    let value = lower_expr(ctx, &positional, vars);
    ctx.prelowered_argument_scopes
        .pop()
        .expect("named argument cache scope must be balanced");
    value
}
fn lower_expr(ctx: &mut LowerCtx, expr: &TypedExpr, vars: &mut HashMap<String, Temp>) -> Temp {
    if let Some(temp) = ctx.prelowered_argument(expr) {
        return temp;
    }
    match &expr.expr {
        semantic::ExprKind::VariantCode(code) => emit_i64_const(ctx, i64::from(*code)),
        semantic::ExprKind::JsonObject(_) | semantic::ExprKind::JsonArray(_) => {
            lower_json_construction(ctx, expr, vars)
        }
        semantic::ExprKind::StructLiteral { fields, .. } => {
            let lowered = fields
                .iter()
                .map(|(name, value)| (name.as_str(), lower_expr(ctx, value, vars)))
                .collect::<Vec<_>>();
            let semantic::Type::Struct {
                fields: declared_fields,
                ..
            } = &expr.ty
            else {
                ctx.record_error("named struct literal lost its declared field layout".into());
                let value = emit_i64_const(ctx, 0);
                return value;
            };
            let mut items = Vec::with_capacity(declared_fields.len());
            for (declared_name, _) in declared_fields.iter() {
                let Some((_, value)) = lowered
                    .iter()
                    .find(|(source_name, _)| *source_name == declared_name.as_str())
                else {
                    ctx.record_error(format!(
                        "named struct literal is missing lowered field `{declared_name}`"
                    ));
                    let placeholder = emit_i64_const(ctx, 0);
                    items.push(placeholder);
                    continue;
                };
                items.push(*value);
            }
            emit_tuple_pack(ctx, items)
        }
        semantic::ExprKind::Tuple(elems) => {
            if elems.is_empty() {
                return emit_i64_const(ctx, 0);
            }
            let mut items = Vec::with_capacity(elems.len());
            for e in elems {
                items.push(lower_expr(ctx, e, vars));
            }
            emit_tuple_pack(ctx, items)
        }
        semantic::ExprKind::List(elements) => lower_list_literal(ctx, elements, &expr.ty, vars),
        semantic::ExprKind::ListComprehension {
            expression,
            item,
            source,
            condition,
        } => lower_list_comprehension(
            ctx,
            expression,
            item,
            source,
            condition.as_deref(),
            &expr.ty,
            vars,
        ),
        semantic::ExprKind::IntLiteral(n) => {
            let t = ctx.new_temp();
            let kind = pointer_kind_for_type(&expr.ty)
                .filter(|kind| {
                    matches!(
                        kind,
                        DataRefKind::Int | DataRefKind::Decimal | DataRefKind::Quantity
                    )
                })
                .unwrap_or_else(|| {
                    ctx.record_error(format!(
                        "integer literal reached lowering with non-numeric type {}",
                        semantic::type_name(&expr.ty)
                    ));
                    DataRefKind::Int
                });
            emit_data_ref_into(ctx, t, kind, n.to_string());
            t
        }
        semantic::ExprKind::DecimalLiteral { value, .. } => {
            let t = ctx.new_temp();
            let kind = pointer_kind_for_type(&expr.ty)
                .filter(|kind| matches!(kind, DataRefKind::Decimal | DataRefKind::Quantity))
                .unwrap_or_else(|| {
                    ctx.record_error(format!(
                        "decimal literal reached lowering with non-decimal type {}",
                        semantic::type_name(&expr.ty)
                    ));
                    DataRefKind::Decimal
                });
            emit_data_ref_into(ctx, t, kind, value.to_string());
            t
        }
        semantic::ExprKind::Bool(b) => emit_i64_const(ctx, if *b { 1 } else { 0 }),
        semantic::ExprKind::String(s) => {
            let t = ctx.new_temp();
            ctx.current_instr(Instr::StringConst {
                dest: t,
                value: s.clone(),
            });
            t
        }
        semantic::ExprKind::Bytes(bytes) => {
            let t = ctx.new_temp();
            let hex = hex::encode(bytes);
            emit_data_ref_into(ctx, t, DataRefKind::Blob, format!("0x{hex}"));
            t
        }
        semantic::ExprKind::Ident(name) => {
            if ctx.state_name_literals.contains_key(name)
                || ctx.state_runtime_roots.contains_key(name)
            {
                if let Some(value) = ctx.state_value_cache.get(name).copied() {
                    return value;
                }
                if let Some(value) = lower_state_binding_value(ctx, name, &expr.ty) {
                    ctx.state_value_cache.insert(name.clone(), value);
                    return value;
                }
            }
            if let Some(temp) = vars.get(name) {
                *temp
            } else {
                ctx.record_error(format!("undefined variable {name}"));
                emit_i64_const(ctx, 0)
            }
        }
        semantic::ExprKind::Unary { op, expr: inner } => {
            let v = lower_expr(ctx, inner, vars);
            if matches!(op, UnaryOp::Neg) && semantic::is_wide_numeric_type(&inner.ty) {
                let kind = wide_numeric_kind_for_type(&inner.ty)
                    .expect("wide numeric unary operand has a nominal ABI kind");
                if kind == WideNumericKind::Quantity {
                    ctx.record_error("quantity is non-negative and cannot be negated".into());
                    let t = ctx.new_temp();
                    ctx.current_instr(Instr::Const { dest: t, value: 0 });
                    return t;
                }
                let t = ctx.new_temp();
                ctx.current_instr(Instr::NumericNeg {
                    dest: t,
                    value: v,
                    kind,
                });
                t
            } else {
                emit_unary(ctx, *op, v)
            }
        }
        semantic::ExprKind::NumericCast { expr: inner } => {
            let v = lower_expr(ctx, inner, vars);
            let src_ty = semantic::resolve_struct_type(&inner.ty);
            let dst_ty = semantic::resolve_struct_type(&expr.ty);
            if src_ty != dst_ty
                && semantic::is_wide_numeric_type(&src_ty)
                && semantic::is_wide_numeric_type(&dst_ty)
            {
                let t = ctx.new_temp();
                ctx.current_instr(Instr::NumericConvert {
                    dest: t,
                    value: v,
                    source: wide_numeric_kind_for_type(&src_ty)
                        .expect("numeric cast source has an ABI kind"),
                    destination: wide_numeric_kind_for_type(&dst_ty)
                        .expect("numeric cast destination has an ABI kind"),
                });
                return t;
            }
            v
        }
        semantic::ExprKind::NumericTryCast { expr: inner } => {
            let value = lower_expr(ctx, inner, vars);
            let source = wide_numeric_kind_for_type(&inner.ty)
                .expect("recoverable numeric cast source has an ABI kind");
            let Type::Result(ok_type, error_type) = semantic::resolve_struct_type(&expr.ty) else {
                ctx.record_error(
                    "internal error: recoverable numeric cast has non-Result type".into(),
                );
                return emit_i64_const(ctx, 0);
            };
            if !matches!(
                semantic::resolve_struct_type(&error_type),
                Type::ErrorEnum(_)
            ) {
                ctx.record_error(
                    "internal error: numeric fault payload must be NumericError".into(),
                );
                return emit_i64_const(ctx, 0);
            }
            let destination = wide_numeric_kind_for_type(&ok_type)
                .expect("recoverable numeric cast destination has an ABI kind");
            let converted = ctx.new_temp();
            let status = ctx.new_temp();
            ctx.current_instr(Instr::NumericTryConvert {
                dest: converted,
                value,
                source,
                destination,
            });
            ctx.current_instr(Instr::NumericStatus { dest: status });
            let zero = emit_i64_const(ctx, 0);
            let succeeded = emit_binary(ctx, BinaryOp::Eq, status, zero);
            let success = ctx.new_label();
            let failure = ctx.new_label();
            let end = ctx.new_label();
            let result = ctx.new_temp();
            ctx.finish_current(Terminator::Branch {
                cond: succeeded,
                then_bb: success,
                else_bb: failure,
            });
            ctx.start_block(success);
            let ok = emit_sum_value(ctx, &expr.ty, 1, Some(converted));
            emit_copy(ctx, result, ok);
            ctx.finish_current(Terminator::Jump(end));
            ctx.start_block(failure);
            let fault = status;
            let error = emit_sum_value(ctx, &expr.ty, 0, Some(fault));
            emit_copy(ctx, result, error);
            ctx.finish_current(Terminator::Jump(end));
            ctx.start_block(end);
            result
        }
        semantic::ExprKind::Binary { op, left, right } => {
            if matches!(op, BinaryOp::And | BinaryOp::Or) {
                return lower_short_circuit_bool(ctx, *op, left, right, vars);
            }
            let l = lower_expr(ctx, left, vars);
            let r = lower_expr(ctx, right, vars);
            let lhs_wide = semantic::is_wide_numeric_type(&left.ty);
            let rhs_wide = semantic::is_wide_numeric_type(&right.ty);
            if matches!(
                op,
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod
            ) && (lhs_wide || rhs_wide)
            {
                let t = ctx.new_temp();
                ctx.current_instr(Instr::NumericBinary {
                    dest: t,
                    op: *op,
                    left: l,
                    right: r,
                    left_kind: wide_numeric_kind_for_type(&left.ty)
                        .expect("numeric binary left operand has an ABI kind"),
                    right_kind: wide_numeric_kind_for_type(&right.ty)
                        .expect("numeric binary right operand has an ABI kind"),
                    result_kind: wide_numeric_kind_for_type(&expr.ty)
                        .expect("numeric binary result has an ABI kind"),
                });
                return t;
            }
            if matches!(
                op,
                BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
            ) && (lhs_wide || rhs_wide)
            {
                let t = ctx.new_temp();
                ctx.current_instr(Instr::NumericCompare {
                    dest: t,
                    op: *op,
                    left: l,
                    right: r,
                    kind: wide_numeric_kind_for_type(&left.ty)
                        .or_else(|| wide_numeric_kind_for_type(&right.ty))
                        .expect("wide numeric comparison has a nominal ABI kind"),
                });
                return t;
            }
            if matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
                let t = emit_typed_value_eq(ctx, l, r, &left.ty);
                if *op == BinaryOp::Ne {
                    let t2 = emit_unary(ctx, UnaryOp::Not, t);
                    return t2;
                }
                return t;
            }
            emit_binary(ctx, *op, l, r)
        }
        semantic::ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let cond_t = lower_expr(ctx, cond, vars);
            let then_label = ctx.new_label();
            let else_label = ctx.new_label();
            let end_label = ctx.new_label();
            let result_words = runtime_value_word_types(&expr.ty)
                .into_iter()
                .map(|_| ctx.new_temp())
                .collect::<Vec<_>>();
            ctx.finish_current(Terminator::Branch {
                cond: cond_t,
                then_bb: then_label,
                else_bb: else_label,
            });
            ctx.start_block(then_label);
            let then_v = lower_expr(ctx, then_expr, &mut vars.clone());
            copy_runtime_value_words(ctx, then_v, &expr.ty, &result_words);
            ctx.finish_current(Terminator::Jump(end_label));
            ctx.start_block(else_label);
            let else_v = lower_expr(ctx, else_expr, &mut vars.clone());
            copy_runtime_value_words(ctx, else_v, &expr.ty, &result_words);
            ctx.finish_current(Terminator::Jump(end_label));
            ctx.start_block(end_label);
            rebuild_runtime_value(ctx, &expr.ty, &result_words)
        }
        semantic::ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let condition = lower_expr(ctx, condition, vars);
            let then_label = ctx.new_label();
            let else_label = ctx.new_label();
            let end_label = ctx.new_label();
            let result_words = runtime_value_word_types(&expr.ty)
                .into_iter()
                .map(|_| ctx.new_temp())
                .collect::<Vec<_>>();
            ctx.finish_current(Terminator::Branch {
                cond: condition,
                then_bb: then_label,
                else_bb: else_label,
            });
            ctx.start_block(then_label);
            if let Some(then_value) = lower_expression_block(ctx, then_branch, &mut vars.clone()) {
                copy_runtime_value_words(ctx, then_value, &expr.ty, &result_words);
                ctx.finish_current(Terminator::Jump(end_label));
            }
            ctx.start_block(else_label);
            if let Some(else_value) = lower_expression_block(ctx, else_branch, &mut vars.clone()) {
                copy_runtime_value_words(ctx, else_value, &expr.ty, &result_words);
                ctx.finish_current(Terminator::Jump(end_label));
            }
            ctx.start_block(end_label);
            rebuild_runtime_value(ctx, &expr.ty, &result_words)
        }
        semantic::ExprKind::IfLet {
            pattern,
            value,
            then_branch,
            else_branch,
        } => {
            let sum = lower_expr(ctx, value, vars);
            let then_label = ctx.new_label();
            let else_label = ctx.new_label();
            let end_label = ctx.new_label();
            branch_on_sum_pattern(ctx, pattern, sum, then_label, else_label);
            let result_words = runtime_value_word_types(&expr.ty)
                .into_iter()
                .map(|_| ctx.new_temp())
                .collect::<Vec<_>>();
            ctx.start_block(then_label);
            let mut then_vars = vars.clone();
            bind_sum_pattern(ctx, pattern, sum, &mut then_vars);
            if let Some(then_value) = lower_expression_block(ctx, then_branch, &mut then_vars) {
                copy_runtime_value_words(ctx, then_value, &expr.ty, &result_words);
                ctx.finish_current(Terminator::Jump(end_label));
            }
            ctx.start_block(else_label);
            if let Some(else_value) = lower_expression_block(ctx, else_branch, &mut vars.clone()) {
                copy_runtime_value_words(ctx, else_value, &expr.ty, &result_words);
                ctx.finish_current(Terminator::Jump(end_label));
            }
            ctx.start_block(end_label);
            rebuild_runtime_value(ctx, &expr.ty, &result_words)
        }
        semantic::ExprKind::Match { value, arms } => {
            if matches!(&value.ty, Type::Enum(_) | Type::ErrorEnum(_)) {
                let code = lower_expr(ctx, value, vars);
                let end = ctx.new_label();
                let result_words = runtime_value_word_types(&expr.ty)
                    .into_iter()
                    .map(|_| ctx.new_temp())
                    .collect::<Vec<_>>();
                for (index, arm) in arms.iter().enumerate() {
                    let body = ctx.new_label();
                    let next = ctx.new_label();
                    if index + 1 == arms.len() {
                        ctx.finish_current(Terminator::Jump(body));
                    } else {
                        let cond = pattern_matches(ctx, &arm.pattern, code);
                        ctx.finish_current(Terminator::Branch {
                            cond,
                            then_bb: body,
                            else_bb: next,
                        });
                    }
                    ctx.start_block(body);
                    if let Some(value) = lower_expression_block(ctx, &arm.body, &mut vars.clone()) {
                        copy_runtime_value_words(ctx, value, &expr.ty, &result_words);
                        ctx.finish_current(Terminator::Jump(end));
                    }
                    if index + 1 < arms.len() {
                        ctx.start_block(next);
                    }
                }
                ctx.start_block(end);
                return rebuild_runtime_value(ctx, &expr.ty, &result_words);
            }
            // Normalize the canonical exhaustive early-return spelling of
            // same-family propagation before CFG construction. This keeps
            // postfix `?` genuine zero-cost syntax sugar: both source forms
            // enter the exact same lowering helper and therefore produce the
            // same optimized IR and executable bytes.
            if propagation_match_return(&value.ty, &ctx.function_return_type, arms).is_some() {
                return lower_propagation(ctx, value, vars);
            }
            let sum = lower_expr(ctx, value, vars);
            let tag = load_sum_tag(ctx, sum);
            let tag_one_arm = arms
                .iter()
                .find(|arm| sum_pattern_tag(&arm.pattern) == 1)
                .expect("semantic analysis guarantees the tag-one arm");
            let tag_zero_arm = arms
                .iter()
                .find(|arm| sum_pattern_tag(&arm.pattern) == 0)
                .expect("semantic analysis guarantees the tag-zero arm");
            let tag_one_label = ctx.new_label();
            let tag_zero_label = ctx.new_label();
            let end_label = ctx.new_label();
            let result_words = runtime_value_word_types(&expr.ty)
                .into_iter()
                .map(|_| ctx.new_temp())
                .collect::<Vec<_>>();
            ctx.finish_current(Terminator::Branch {
                cond: tag,
                then_bb: tag_one_label,
                else_bb: tag_zero_label,
            });
            ctx.start_block(tag_one_label);
            let mut tag_one_vars = vars.clone();
            bind_sum_pattern(ctx, &tag_one_arm.pattern, sum, &mut tag_one_vars);
            if let Some(tag_one_value) =
                lower_expression_block(ctx, &tag_one_arm.body, &mut tag_one_vars)
            {
                copy_runtime_value_words(ctx, tag_one_value, &expr.ty, &result_words);
                ctx.finish_current(Terminator::Jump(end_label));
            }
            ctx.start_block(tag_zero_label);
            let mut tag_zero_vars = vars.clone();
            bind_sum_pattern(ctx, &tag_zero_arm.pattern, sum, &mut tag_zero_vars);
            if let Some(tag_zero_value) =
                lower_expression_block(ctx, &tag_zero_arm.body, &mut tag_zero_vars)
            {
                copy_runtime_value_words(ctx, tag_zero_value, &expr.ty, &result_words);
                ctx.finish_current(Terminator::Jump(end_label));
            }
            ctx.start_block(end_label);
            rebuild_runtime_value(ctx, &expr.ty, &result_words)
        }
        semantic::ExprKind::OptionSome { value } => {
            let payload = lower_expr(ctx, value, vars);
            emit_sum_value(ctx, &expr.ty, 1, Some(payload))
        }
        semantic::ExprKind::OptionNone => emit_sum_value(ctx, &expr.ty, 0, None),
        semantic::ExprKind::ResultOk { value } => {
            let payload = lower_expr(ctx, value, vars);
            emit_sum_value(ctx, &expr.ty, 1, Some(payload))
        }
        semantic::ExprKind::ResultErr { error } => {
            let payload = lower_expr(ctx, error, vars);
            emit_sum_value(ctx, &expr.ty, 0, Some(payload))
        }
        semantic::ExprKind::Propagate { value } => lower_propagation(ctx, value, vars),
        semantic::ExprKind::NamedCall {
            target: name,
            args,
            evaluation_order,
        } => lower_named_call(ctx, &expr.ty, name, args, evaluation_order, vars),
        semantic::ExprKind::Call { target, args } => match target {
            semantic::CallTarget::User(name) => lower_user_call(ctx, name, args, &expr.ty, vars),
            semantic::CallTarget::Contract(method) => {
                lower_contract_call(ctx, method, args, &expr.ty, vars)
            }
            semantic::CallTarget::Intrinsic(intrinsic) => {
                let name = *intrinsic;
                if name == CompilerIntrinsic::ContractAt {
                    return lower_expr(ctx, &args[0], vars);
                }
                if name == CompilerIntrinsic::EmitEvent {
                    return lower_event_emission(ctx, args, vars);
                }
                if let Some(value) = lower_state_page_intrinsic(ctx, name, args, &expr.ty, vars) {
                    return value;
                }
                if let Some(value) = lower_numeric_round_intrinsic(ctx, name, args, vars) {
                    return value;
                }
                if let Some(value) = lower_decimal_to_int_intrinsic(ctx, name, args, vars) {
                    return value;
                }
                if let Some(value) = lower_list_intrinsic(ctx, name, args, &expr.ty, vars) {
                    return value;
                }
                if let Some(value) = lower_sum_type_call(ctx, name, args, &expr.ty, vars) {
                    return value;
                }
                ctx.record_error(format!(
                    "internal error: unhandled typed intrinsic `{name}`"
                ));
                emit_i64_const(ctx, 0)
            }
            semantic::CallTarget::Builtin(builtin) => match builtin {
                Builtin::TestInvokeEntrypoint | Builtin::TestInvokeEntrypointAs => {
                    let (actor, target_index) = if *builtin == Builtin::TestInvokeEntrypointAs {
                        let actor = match args[0].kind() {
                            semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                            _ => panic!("invoke_entrypoint_as actor must be a literal string"),
                        };
                        (Some(actor), 1)
                    } else {
                        (None, 0)
                    };
                    let entrypoint = match args[target_index].kind() {
                        semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                        _ => panic!("runtime entrypoint must be a literal string"),
                    };
                    let (payload, argument_words) =
                        lower_test_argument_record(ctx, &args[target_index + 1], vars);
                    emit_test_call_site(ctx, args.get(target_index + 2), vars);
                    match &expr.ty {
                        semantic::Type::Unit => {
                            ctx.current_instr(Instr::InvokeEntrypointAs {
                                dest: None,
                                actor,
                                entrypoint,
                                payload,
                                argument_words,
                            });
                            emit_i64_const(ctx, 0)
                        }
                        aggregate if function_value_word_types(aggregate).is_some() => {
                            let word_types = function_value_word_types(aggregate)
                                .expect("aggregate return word types checked");
                            let dests: Vec<Temp> =
                                word_types.iter().map(|_| ctx.new_temp()).collect();
                            ctx.current_instr(Instr::InvokeEntrypointAsMulti {
                                dests: dests.clone(),
                                actor,
                                entrypoint,
                                payload,
                                argument_words,
                            });
                            let mut index = 0_usize;
                            let value = rebuild_function_value_from_words(
                                ctx, aggregate, &dests, &mut index,
                            )
                            .expect("validated aggregate return must rebuild from ABI words");
                            debug_assert_eq!(index, dests.len());
                            value
                        }
                        _ => {
                            let dest = ctx.new_temp();
                            ctx.current_instr(Instr::InvokeEntrypointAs {
                                dest: Some(dest),
                                actor,
                                entrypoint,
                                payload,
                                argument_words,
                            });
                            dest
                        }
                    }
                }
                Builtin::TestExpectRejectAs | Builtin::TestExpectAnyRejectAs => {
                    let actor = match args[0].kind() {
                        semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                        _ => panic!("expect_reject_as actor must be a literal string"),
                    };
                    let entrypoint = match args[1].kind() {
                        semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                        _ => panic!("expect_reject_as entrypoint must be a literal string"),
                    };
                    let (payload, argument_words) = lower_test_argument_record(ctx, &args[2], vars);
                    let expectation = lower_expr(ctx, &args[3], vars);
                    emit_test_call_site(ctx, args.get(4), vars);
                    ctx.current_instr(Instr::ExpectRejectAs {
                        actor,
                        entrypoint,
                        payload,
                        argument_words,
                        expectation,
                    });
                    emit_i64_const(ctx, 0)
                }
                Builtin::TestActorAccount => {
                    let actor = match args[0].kind() {
                        semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                        _ => panic!("actor_account actor must be a literal string"),
                    };
                    emit_test_call_site(ctx, args.get(1), vars);
                    let dest = ctx.new_temp();
                    ctx.current_instr(Instr::ActorAccount { dest, actor });
                    dest
                }
                Builtin::TestActorPublicKey => {
                    let actor = match args[0].kind() {
                        semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                        _ => panic!("actor_public_key actor must be a literal string"),
                    };
                    emit_test_call_site(ctx, args.get(1), vars);
                    let dest = ctx.new_temp();
                    ctx.current_instr(Instr::ActorPublicKey { dest, actor });
                    dest
                }
                Builtin::TestActorSign => {
                    let actor = match args[0].kind() {
                        semantic::ExprKind::String(value) => lower_blob_literal(ctx, value),
                        _ => panic!("actor_sign actor must be a literal string"),
                    };
                    let message = lower_expr(ctx, &args[1], vars);
                    emit_test_call_site(ctx, args.get(2), vars);
                    let dest = ctx.new_temp();
                    ctx.current_instr(Instr::ActorSign {
                        dest,
                        actor,
                        message,
                    });
                    dest
                }
                builtin => lower_surface_builtin_call(ctx, *builtin, args, &expr.ty, vars),
            },
        },
        semantic::ExprKind::Index { .. } => {
            // Typed source lowering never contains an rvalue map index: an
            // absent durable key must be represented by Option<V>. Keep this
            // fail-closed guard for callers that construct typed HIR directly.
            ctx.record_error(
                "E_STATE_MAP_OPTIONAL_READ: StateMap rvalue indexing is invalid; use `map.get(key)`"
                    .into(),
            );
            emit_i64_const(ctx, 0)
        }
        semantic::ExprKind::Member { object, field } => {
            // Resolve any explicitly registered durable projection. Local
            // products must instead project from their current SSA root: a
            // flattened local can refer to the value before a loop backedge.
            fn flatten_member_chain(e: &semantic::TypedExpr) -> Option<(String, Vec<usize>)> {
                match e.kind() {
                    semantic::ExprKind::Member { object, field } => {
                        let (base, mut rest) = flatten_member_chain(object)?;
                        let idx = if let Ok(i) = field.parse::<usize>() {
                            Some(i)
                        } else {
                            match crate::semantic::resolve_struct_type(&object.ty) {
                                crate::semantic::Type::Struct { fields, .. } => {
                                    fields.iter().position(|(fname, _)| fname == field)
                                }
                                crate::semantic::Type::Tuple(_) => field.parse::<usize>().ok(),
                                _ => None,
                            }
                        }?;
                        rest.push(idx);
                        Some((base, rest))
                    }
                    semantic::ExprKind::Ident(nm) => Some((nm.clone(), Vec::new())),
                    _ => None,
                }
            }
            if let Some((base, indices)) = flatten_member_chain(expr)
                && !indices.is_empty()
            {
                // Recursion already collects indices from the root outward.
                let mut name = base;
                for i in indices {
                    name.push('#');
                    name.push_str(&i.to_string());
                }
                if ctx.state_name_literals.contains_key(&name) {
                    if let Some(value) = ctx.state_value_cache.get(&name).copied() {
                        return value;
                    }
                    if let Some(value) = lower_state_binding_value(ctx, &name, &expr.ty) {
                        ctx.state_value_cache.insert(name.clone(), value);
                        return value;
                    }
                }
            }
            // Generic tuple/struct field access via TupleGet when index is numeric.
            if let Ok(idx) = field.parse::<usize>() {
                let tup = lower_expr(ctx, object, vars);
                let out = emit_tuple_get(ctx, tup, idx);
                return out;
            }
            // Named struct fields: map to tuple index using type info.
            if let crate::semantic::Type::Struct { fields, .. } =
                crate::semantic::resolve_struct_type(&object.ty)
                && let Some((idx, _)) = fields
                    .iter()
                    .enumerate()
                    .find(|(_, (fname, _))| fname == field)
            {
                let tup = lower_expr(ctx, object, vars);
                let out = emit_tuple_get(ctx, tup, idx);
                return out;
            }
            // Semantic analysis must prove every member against a tuple or named
            // struct before typed HIR reaches lowering. Keep a sentinel value only
            // to preserve IR construction after recording the fatal error; callers
            // must never receive bytecode for this malformed typed expression.
            ctx.record_error(format!(
                "typed member `{field}` has no Kotodama V1 lowering for `{}`",
                crate::semantic::type_name(&object.ty)
            ));
            emit_i64_const(ctx, 0)
        }
    }
}
fn lower_sum_type_call(
    ctx: &mut LowerCtx,
    name: CompilerIntrinsic,
    args: &[semantic::TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Option<Temp> {
    Some(match name {
        CompilerIntrinsic::StateMapGet => lower_state_map_get_option(ctx, args, vars),
        CompilerIntrinsic::IsSome | CompilerIntrinsic::IsOk => {
            let tagged_value = lower_expr(ctx, &args[0], vars);
            load_sum_tag(ctx, tagged_value)
        }
        CompilerIntrinsic::IsNone | CompilerIntrinsic::IsErr => {
            let tagged_value = lower_expr(ctx, &args[0], vars);
            let tag = load_sum_tag(ctx, tagged_value);
            emit_unary(ctx, UnaryOp::Not, tag)
        }
        CompilerIntrinsic::UnwrapOr => lower_tagged_unwrap(ctx, &args[0], &args[1], true, vars),
        CompilerIntrinsic::UnwrapErrOr => lower_tagged_unwrap(ctx, &args[0], &args[1], false, vars),
        CompilerIntrinsic::Expect
        | CompilerIntrinsic::OptionOkOr
        | CompilerIntrinsic::ResultOrErr => {
            lower_sum_error_bridge(ctx, name, args, result_ty, vars)
        }
        _ => return None,
    })
}
fn lower_sum_error_bridge(
    ctx: &mut LowerCtx,
    name: CompilerIntrinsic,
    args: &[semantic::TypedExpr],
    result_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let tagged = lower_expr(ctx, &args[0], vars);
    let payload_ty = match semantic::resolve_struct_type(&args[0].ty) {
        Type::Option(value) | Type::Result(value, _) => value,
        _ => unreachable!("typed sum error bridge receiver"),
    };
    let tag = load_sum_tag(ctx, tagged);
    let success = ctx.new_label();
    let failure = ctx.new_label();
    ctx.finish_current(Terminator::Branch {
        cond: tag,
        then_bb: success,
        else_bb: failure,
    });
    ctx.start_block(failure);
    let error = lower_expr(ctx, &args[1], vars);
    if name == CompilerIntrinsic::Expect {
        let Type::ErrorEnum(error_type) = semantic::resolve_struct_type(&args[1].ty) else {
            unreachable!("typed nominal sum expectation error")
        };
        let encoded = ivm_abi::codec::encode_canonical_norito(error_type.as_ref())
            .expect("validated nominal error schema encodes");
        let descriptor = emit_data_ref(
            ctx,
            DataRefKind::NoritoBytes,
            format!("0x{}", hex::encode(encoded)),
        );
        let reject = emit_i64_const(ctx, 1);
        ctx.current_instr(Instr::AbortIf {
            cond: reject,
            descriptor,
            code: error,
        });
        // AbortIf is unconditional here. The shared success continuation has
        // no synthesized value for the inactive branch.
        ctx.finish_current(Terminator::Jump(success));
        ctx.start_block(success);
        return load_sum_payload(ctx, tagged, &payload_ty);
    }
    let end = ctx.new_label();
    let output = ctx.new_temp();
    let rejected = emit_sum_value(ctx, result_ty, 0, Some(error));
    emit_copy(ctx, output, rejected);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(success);
    let payload = load_sum_payload(ctx, tagged, &payload_ty);
    let accepted = emit_sum_value(ctx, result_ty, 1, Some(payload));
    emit_copy(ctx, output, accepted);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    output
}
fn lower_tagged_unwrap(
    ctx: &mut LowerCtx,
    tagged_expr: &semantic::TypedExpr,
    fallback_expr: &semantic::TypedExpr,
    payload_when_tagged: bool,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let tagged = lower_expr(ctx, tagged_expr, vars);
    // `unwrap_or` is eager (the lazy spelling would be `unwrap_or_else`, which
    // V1 does not expose), so capture the fallback before branching. This also
    // keeps positional and named-call evaluation semantics identical.
    let fallback = lower_expr(ctx, fallback_expr, vars);
    let tag = load_sum_tag(ctx, tagged);
    let payload_block = ctx.new_label();
    let fallback_block = ctx.new_label();
    let end_block = ctx.new_label();
    let (then_bb, else_bb) = if payload_when_tagged {
        (payload_block, fallback_block)
    } else {
        (fallback_block, payload_block)
    };
    ctx.finish_current(Terminator::Branch {
        cond: tag,
        then_bb,
        else_bb,
    });
    let payload_ty = semantic::resolve_struct_type(&fallback_expr.ty);
    let result_words = runtime_value_word_types(&payload_ty)
        .into_iter()
        .map(|_| ctx.new_temp())
        .collect::<Vec<_>>();
    ctx.start_block(payload_block);
    let payload = load_sum_payload(ctx, tagged, &payload_ty);
    copy_runtime_value_words(ctx, payload, &payload_ty, &result_words);
    ctx.finish_current(Terminator::Jump(end_block));
    ctx.start_block(fallback_block);
    copy_runtime_value_words(ctx, fallback, &payload_ty, &result_words);
    ctx.finish_current(Terminator::Jump(end_block));
    ctx.start_block(end_block);
    rebuild_runtime_value(ctx, &payload_ty, &result_words)
}
/// Convert a host's nullable public pointer into the ordinary nominal Option layout.
fn lower_nullable_pointer(ctx: &mut LowerCtx, pointer: Temp, payload_type: &Type) -> Temp {
    let option = Type::Option(Box::new(payload_type.clone()));
    let some_block = ctx.new_label();
    let none_block = ctx.new_label();
    let end = ctx.new_label();
    let output = ctx.new_temp();
    ctx.finish_current(Terminator::Branch {
        cond: pointer,
        then_bb: some_block,
        else_bb: none_block,
    });
    ctx.start_block(some_block);
    let some = emit_sum_value(ctx, &option, 1, Some(pointer));
    emit_copy(ctx, output, some);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(none_block);
    let none = emit_sum_value(ctx, &option, 0, None);
    emit_copy(ctx, output, none);
    ctx.finish_current(Terminator::Jump(end));
    ctx.start_block(end);
    output
}
/// Decode a present durable value and materialize the selected `Option` arm.
///
/// The absent branch allocates only a tag-bearing `Option::none`; it never
/// constructs or evaluates a value payload.
fn lower_present_or_inactive_state_value(
    ctx: &mut LowerCtx,
    blob: Temp,
    present: Temp,
    value_ty: &Type,
    delete_when_present: Option<Temp>,
) -> Option<Temp> {
    let resolved = semantic::resolve_struct_type(value_ty);
    state_value_schema(&resolved)?.word_kinds()?;
    let option_ty = Type::Option(Box::new(resolved.clone()));
    let result = ctx.new_temp();
    let present_block = ctx.new_label();
    let absent_block = ctx.new_label();
    let end_block = ctx.new_label();
    ctx.finish_current(Terminator::Branch {
        cond: present,
        then_bb: present_block,
        else_bb: absent_block,
    });
    ctx.start_block(present_block);
    let decoded = decode_aggregate_state_value(ctx, blob, &resolved)?;
    let some = emit_sum_value(ctx, &option_ty, 1, Some(decoded));
    emit_copy(ctx, result, some);
    if let Some(path) = delete_when_present {
        ctx.current_instr(Instr::StateDel { path });
    }
    ctx.finish_current(Terminator::Jump(end_block));
    ctx.start_block(absent_block);
    let none = emit_sum_value(ctx, &option_ty, 0, None);
    emit_copy(ctx, result, none);
    ctx.finish_current(Terminator::Jump(end_block));
    ctx.start_block(end_block);
    Some(result)
}
fn state_map_value_type(map: &semantic::TypedExpr) -> Option<Type> {
    match semantic::resolve_struct_type(&map.ty) {
        Type::StateMap(_, value) => Some(*value),
        _ => None,
    }
}
fn lower_state_map_get_option(
    ctx: &mut LowerCtx,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let map = &args[0];
    let key = lower_expr(ctx, &args[1], vars);
    let declared_value_ty = state_map_value_type(map).unwrap_or(Type::Unit);
    let Some(base) = state_map_base_name(map) else {
        ctx.record_error("StateMap.get receiver is not a durable state map".into());
        return lower_absent_option(ctx, &declared_value_ty);
    };
    let Some(spec) = ctx.state_map_configs.get(&base).cloned() else {
        ctx.record_error(format!("StateMap.get receiver `{base}` is not declared"));
        return lower_absent_option(ctx, &declared_value_ty);
    };
    let Some(key_type) = state_map_key_type(&spec.key) else {
        ctx.record_error("StateMap.get key type is not lowerable".into());
        return lower_absent_option(ctx, &spec.value);
    };
    let path = build_state_map_path(ctx, &base, key, &key_type);
    let blob = ctx.new_temp();
    ctx.current_instr(Instr::StateGet { dest: blob, path });
    let zero = emit_i64_const(ctx, 0);
    let present = emit_binary(ctx, BinaryOp::Ne, blob, zero);
    lower_present_or_inactive_state_value(ctx, blob, present, &spec.value, None).unwrap_or_else(
        || {
            ctx.record_error("StateMap.get value type is not lowerable".into());
            lower_absent_option(ctx, &spec.value)
        },
    )
}
fn lower_state_map_remove_option(
    ctx: &mut LowerCtx,
    args: &[semantic::TypedExpr],
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    let map = &args[0];
    let key = lower_expr(ctx, &args[1], vars);
    let declared_value_ty = state_map_value_type(map).unwrap_or(Type::Unit);
    let Some(base) = state_map_base_name(map) else {
        ctx.record_error("StateMap.remove receiver is not a durable state map".into());
        return lower_absent_option(ctx, &declared_value_ty);
    };
    let Some(spec) = ctx.state_map_configs.get(&base).cloned() else {
        ctx.record_error(format!("StateMap.remove receiver `{base}` is not declared"));
        return lower_absent_option(ctx, &declared_value_ty);
    };
    let Some(key_type) = state_map_key_type(&spec.key) else {
        ctx.record_error("StateMap.remove key type is not lowerable".into());
        return lower_absent_option(ctx, &spec.value);
    };
    let path = build_state_map_path(ctx, &base, key, &key_type);
    let blob = ctx.new_temp();
    ctx.current_instr(Instr::StateGet { dest: blob, path });
    let zero = emit_i64_const(ctx, 0);
    let present = emit_binary(ctx, BinaryOp::Ne, blob, zero);
    lower_present_or_inactive_state_value(ctx, blob, present, &spec.value, Some(path))
        .unwrap_or_else(|| {
            ctx.record_error("StateMap.remove value type is not lowerable".into());
            lower_absent_option(ctx, &spec.value)
        })
}
fn lower_absent_option(ctx: &mut LowerCtx, value_ty: &Type) -> Temp {
    emit_sum_value(
        ctx,
        &Type::Option(Box::new(semantic::resolve_struct_type(value_ty))),
        0,
        None,
    )
}
fn account_id_literal_uses_alias_resolution(raw: &str) -> bool {
    if iroha_data_model::account::AccountId::parse_encoded(raw).is_ok() {
        return false;
    }
    // Keep alias detection intentionally broad so alias-shaped literals continue into the
    // runtime host resolver, which validates the current catalog/binding instead of failing
    // during static AccountId encoding.
    raw.contains('@')
}
fn lower_state_binding_value(ctx: &mut LowerCtx, name: &str, ty: &Type) -> Option<Temp> {
    let resolved = semantic::resolve_struct_type(ty);
    let blob = state_get_blob_for_name(ctx, name);
    if !is_canonical_state_value_type(&resolved) {
        return None;
    }
    decode_aggregate_state_value(ctx, blob, &resolved)
}
fn state_get_blob_for_name(ctx: &mut LowerCtx, name: &str) -> Temp {
    let path = build_state_root_path(ctx, name);
    let blob = ctx.new_temp();
    ctx.current_instr(Instr::StateGet { dest: blob, path });
    blob
}
struct LoopContext {
    continue_label: Label,
    break_label: Label,
    phi: Option<HashMap<String, Temp>>,
}
struct LowerCtx {
    next_temp: usize,
    next_label: usize,
    current_source: Option<crate::source::SourceRange>,
    blocks: Vec<BasicBlock>,
    current: Option<BasicBlock>,
    loop_stack: Vec<LoopContext>,
    /// Source binding layouts used to carry product leaves through CFG joins.
    binding_types: HashMap<String, Type>,
    /// Stable machine-word destinations behind each virtual loop-carried product.
    product_loop_phis: HashMap<Temp, (Type, Vec<Temp>)>,
    /// Metadata for top-level state maps lowered to durable state syscalls.
    state_map_configs: HashMap<String, StateMapSpec>,
    /// Mapping from top-level state identifiers to Name literals used in TLVs.
    state_name_literals: HashMap<String, String>,
    /// Runtime Name roots for `state` helper parameters.
    state_runtime_roots: HashMap<String, Temp>,
    /// Durable values valid only in the current basic block since its last
    /// possible state mutation. Keep these out of local SSA environments so
    /// branch merges and loop backedges cannot restore stale memory values.
    state_value_cache: HashMap<String, Temp>,
    /// Dynamic iteration cap for first-release dynamic bounds.
    _dyn_iter_cap: usize,
    /// Declared return type used when `?` must materialize a differently-sized
    /// failure value for the enclosing function.
    function_return_type: Type,
    call_renames: HashMap<String, String>,
    function_param_specs: HashMap<String, Vec<TypedParam>>,
    /// Scoped compiler-only identities for named arguments already evaluated
    /// in source order. Raw pointers are compared only while the owning typed
    /// expression Vec is alive and are never dereferenced.
    prelowered_argument_scopes: Vec<Vec<(*const TypedExpr, Temp)>>,
    error: Option<String>,
}
impl LowerCtx {
    fn new(
        function_return_type: Type,
        dyn_iter_cap: usize,
        call_renames: HashMap<String, String>,
        function_param_specs: HashMap<String, Vec<TypedParam>>,
    ) -> Self {
        Self {
            next_temp: 0,
            next_label: 0,
            current_source: None,
            blocks: Vec::new(),
            current: None,
            loop_stack: Vec::new(),
            binding_types: HashMap::new(),
            product_loop_phis: HashMap::new(),
            state_map_configs: Default::default(),
            state_name_literals: Default::default(),
            state_runtime_roots: Default::default(),
            state_value_cache: Default::default(),
            _dyn_iter_cap: dyn_iter_cap,
            function_return_type,
            call_renames,
            function_param_specs,
            prelowered_argument_scopes: Vec::new(),
            error: None,
        }
    }
    fn product_binding_type(&self, name: &str) -> Option<Type> {
        self.binding_types.get(name).and_then(|ty| {
            let ty = semantic::resolve_struct_type(ty);
            matches!(ty, Type::Struct { .. } | Type::Tuple(_)).then_some(ty)
        })
    }
    fn prelowered_argument(&self, expression: &TypedExpr) -> Option<Temp> {
        let identity = std::ptr::from_ref(expression);
        self.prelowered_argument_scopes
            .iter()
            .rev()
            .flat_map(|scope| scope.iter())
            .find_map(|(candidate, temp)| std::ptr::eq(*candidate, identity).then_some(*temp))
    }
    fn new_temp(&mut self) -> Temp {
        let t = Temp(self.next_temp);
        self.next_temp += 1;
        t
    }
    fn new_label(&mut self) -> Label {
        let l = Label(self.next_label);
        self.next_label += 1;
        l
    }
    fn start_block(&mut self, label: Label) {
        self.state_value_cache.clear();
        if self.current.is_some() {
            self.record_error("internal error: current block not finished".to_string());
            self.current = None;
        }
        self.current = Some(BasicBlock {
            label,
            instrs: self
                .current_source
                .map(|source| Instr::Source(Some(source)))
                .into_iter()
                .collect(),
            terminator: Terminator::Jump(label),
        });
    }
    fn set_source(&mut self, source: Option<crate::source::SourceRange>) {
        if self.current_source != source {
            self.current_source = source;
            if let Some(block) = &mut self.current {
                block.instrs.push(Instr::Source(source));
            }
        }
    }
    fn current_instr(&mut self, instr: Instr) {
        if matches!(
            &instr,
            Instr::Call { .. }
                | Instr::CallMulti { .. }
                | Instr::StateSet { .. }
                | Instr::StateDel { .. }
                | Instr::CallContract { .. }
                | Instr::InvokeEntrypointAs { .. }
                | Instr::InvokeEntrypointAsMulti { .. }
                | Instr::ExpectRejectAs { .. }
                | Instr::DirectHelperSyscall { .. }
                | Instr::VendorExecuteInstruction { .. }
                | Instr::SmartContractLifecycle { .. }
                | Instr::SoracloudHostCall { .. }
        ) {
            self.state_value_cache.clear();
        }
        if let Some(ref mut bb) = self.current {
            bb.instrs.push(instr);
        }
    }
    fn finish_current(&mut self, term: Terminator) {
        let Some(mut bb) = self.current.take() else {
            self.record_error("internal error: no current block".to_string());
            return;
        };
        bb.terminator = term;
        self.blocks.push(bb);
    }
    fn push_loop(&mut self, cont: Label, brk: Label) {
        self.loop_stack.push(LoopContext {
            continue_label: cont,
            break_label: brk,
            phi: None,
        });
    }
    fn pop_loop(&mut self) {
        self.loop_stack.pop();
    }
    fn record_error(&mut self, message: String) {
        if self.error.is_none() {
            self.error = Some(message);
        }
    }
    fn call_target(&self, name: &str) -> String {
        self.call_renames
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }
    fn loop_targets(&self) -> Option<(Label, Label)> {
        self.loop_stack
            .last()
            .map(|ctx| (ctx.continue_label, ctx.break_label))
    }
    fn set_loop_phi(&mut self, phi: HashMap<String, Temp>) {
        if let Some(ctx) = self.loop_stack.last_mut() {
            ctx.phi = Some(phi);
        }
    }
    fn current_loop_phi(&self) -> Option<&HashMap<String, Temp>> {
        self.loop_stack.last().and_then(|ctx| ctx.phi.as_ref())
    }
}
fn build_state_name_literal(ctx: &mut LowerCtx, name: &str) -> Temp {
    let t_base = ctx.new_temp();
    let literal = ctx
        .state_name_literals
        .get(name)
        .cloned()
        .unwrap_or_else(|| name.to_string());
    emit_data_ref_into(ctx, t_base, DataRefKind::Name, literal);
    t_base
}
fn build_state_base_name(ctx: &mut LowerCtx, name: &str) -> Temp {
    if let Some(temp) = ctx.state_runtime_roots.get(name).copied() {
        temp
    } else {
        build_state_name_literal(ctx, name)
    }
}
fn build_state_path_literal(ctx: &mut LowerCtx, name: &str) -> Temp {
    let literal = ctx
        .state_name_literals
        .get(name)
        .cloned()
        .unwrap_or_else(|| name.to_string());
    let encoded = StatePath::try_from(literal.clone())
        .map_err(|error| format!("invalid durable StatePath `{literal}`: {error}"))
        .and_then(|path| {
            ivm_abi::codec::encode_canonical_norito(&path)
                .map_err(|error| format!("failed to encode durable StatePath `{literal}`: {error}"))
        });
    let value = match encoded {
        Ok(bytes) => format!("0x{}", hex::encode(bytes)),
        Err(error) => {
            ctx.record_error(error);
            "0x".to_owned()
        }
    };
    let path = ctx.new_temp();
    ctx.current_instr(Instr::DataRef {
        dest: path,
        kind: DataRefKind::NoritoBytes,
        value,
    });
    path
}
fn build_state_root_path(ctx: &mut LowerCtx, name: &str) -> Temp {
    if let Some(root) = ctx.state_runtime_roots.get(name).copied() {
        let path = ctx.new_temp();
        ctx.current_instr(Instr::StatePathFromName {
            dest: path,
            name: root,
        });
        path
    } else {
        build_state_path_literal(ctx, name)
    }
}
fn build_state_map_path(ctx: &mut LowerCtx, name: &str, key: Temp, key_type: &Type) -> Temp {
    let base = build_state_base_name(ctx, name);
    let key_blob = encode_aggregate_state_value(ctx, key, key_type)
        .expect("validated canonical durable map key schema");
    let path = ctx.new_temp();
    ctx.current_instr(Instr::PathMapKeyNorito {
        dest: path,
        base,
        key_blob,
    });
    path
}
fn lowerable_state_handle_name(ctx: &LowerCtx, expr: &semantic::TypedExpr) -> Option<String> {
    match expr.kind() {
        semantic::ExprKind::Ident(name) => {
            if ctx.state_runtime_roots.contains_key(name)
                || ctx.state_name_literals.contains_key(name)
            {
                Some(name.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}
fn lower_short_circuit_bool(
    ctx: &mut LowerCtx,
    op: BinaryOp,
    left: &semantic::TypedExpr,
    right: &semantic::TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    debug_assert!(matches!(op, BinaryOp::And | BinaryOp::Or));
    let left_value = lower_expr(ctx, left, vars);
    let rhs_label = ctx.new_label();
    let short_label = ctx.new_label();
    let join_label = ctx.new_label();
    let result = ctx.new_temp();
    let (then_bb, else_bb, short_value) = match op {
        BinaryOp::And => (rhs_label, short_label, 0),
        BinaryOp::Or => (short_label, rhs_label, 1),
        _ => unreachable!("short-circuit lowering only accepts logical operators"),
    };
    ctx.finish_current(Terminator::Branch {
        cond: left_value,
        then_bb,
        else_bb,
    });
    // Materialize the short-circuit result without evaluating the right-hand side.
    // Both predecessors use `Copy` so compiler fact propagation treats `result` as
    // a genuine control-flow merge rather than a block-local constant.
    ctx.start_block(short_label);
    let short_result = emit_i64_const(ctx, short_value);
    emit_copy(ctx, result, short_result);
    ctx.finish_current(Terminator::Jump(join_label));
    ctx.start_block(rhs_label);
    let right_value = lower_expr(ctx, right, &mut vars.clone());
    emit_copy(ctx, result, right_value);
    ctx.finish_current(Terminator::Jump(join_label));
    ctx.start_block(join_label);
    result
}
fn lower_state_handle_arg(
    ctx: &mut LowerCtx,
    expr: &semantic::TypedExpr,
    vars: &mut HashMap<String, Temp>,
) -> Temp {
    if let Some(base_name) = lowerable_state_handle_name(ctx, expr) {
        build_state_base_name(ctx, &base_name)
    } else {
        ctx.record_error("state parameter arguments must reference a durable state handle".into());
        let t = ctx.new_temp();
        ctx.current_instr(Instr::Const { dest: t, value: 0 });
        // Use vars to keep parity with the regular lower_expr signature.
        let _ = vars;
        t
    }
}
fn lower_state_handle_args(
    ctx: &mut LowerCtx,
    expr: &semantic::TypedExpr,
    param_ty: &Type,
    vars: &mut HashMap<String, Temp>,
) -> Vec<Temp> {
    let Some(base_name) = lowerable_state_handle_name(ctx, expr) else {
        return vec![lower_state_handle_arg(ctx, expr, vars)];
    };
    let mut handles = Vec::new();
    collect_state_handle_specs(&base_name, param_ty, &mut handles);
    handles
        .into_iter()
        .map(|(name, _)| build_state_base_name(ctx, &name))
        .collect()
}
fn emit_state_set(ctx: &mut LowerCtx, name: &str, ty: &Type, value: Temp) {
    let resolved = semantic::resolve_struct_type(ty);
    let Some(encoded) = encode_aggregate_state_value(ctx, value, &resolved) else {
        ctx.record_error("durable state value is not encodable".into());
        return;
    };
    let path = build_state_root_path(ctx, name);
    ctx.current_instr(Instr::StateSet {
        path,
        value: encoded,
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parser::parse_test_fragment as parse, semantic::analyze};

    #[test]
    fn public_lowering_apis_handoff_from_a_small_caller() {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let source =
            format!("module StackMargin {{ fn value() {{ let nested = {expression}; }} }}");
        std::thread::Builder::new()
            .name("kotodama-small-lowering-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let program = crate::parser::parse(&source)
                    .expect("boundary-depth lowering fixture must parse");
                let typed = crate::semantic::analyze(&program)
                    .expect("boundary-depth lowering fixture must type-check");
                let lowered =
                    lower(&typed).expect("default lowering must use the bounded compiler worker");
                assert_eq!(lowered.functions.len(), 1);
                drop(lowered);
                let lowered =
                    lower_with_cap(&typed, crate::semantic::COLLECTION_ITERATION_LIMIT as usize)
                        .expect("capped lowering must use the bounded compiler worker");
                assert_eq!(lowered.functions.len(), 1);
                drop(lowered);
                drop(typed);
                drop(program);
            })
            .expect("spawn small lowering caller")
            .join()
            .expect("public lowering APIs must not consume the caller stack");
    }

    #[test]
    fn malformed_typed_member_access_fails_closed_during_lowering() {
        let mut context = LowerCtx::new(Type::Unit, 64, HashMap::new(), HashMap::new());
        let entry = context.new_label();
        context.start_block(entry);
        let malformed = TypedExpr {
            expr: semantic::ExprKind::Member {
                object: Box::new(TypedExpr {
                    expr: semantic::ExprKind::Bool(true),
                    ty: Type::Bool,
                }),
                field: "missing".to_owned(),
            },
            ty: Type::Int,
        };
        let _sentinel = lower_expr(&mut context, &malformed, &mut HashMap::new());
        assert_eq!(
            context.error.as_deref(),
            Some("typed member `missing` has no Kotodama V1 lowering for `bool`")
        );
    }
    #[test]
    fn source_int_and_internal_scalar_have_an_explicit_ir_boundary() {
        let mut context = LowerCtx::new(Type::Unit, 64, HashMap::new(), HashMap::new());
        let entry = context.new_label();
        context.start_block(entry);
        let scalar = emit_i64_const(&mut context, 17);
        let source_int = emit_int_from_i64(&mut context, scalar);
        context.finish_current(Terminator::Return(Some(source_int)));
        assert!(matches!(
            context.blocks[0].instrs.as_slice(),
            [
                Instr::Const {
                    dest: actual_scalar,
                    value: 17,
                },
                Instr::IntFromI64 {
                    dest: actual_source,
                    value,
                },
            ] if *actual_scalar == scalar && *actual_source == source_int && *value == scalar
        ));
        let mut context = LowerCtx::new(Type::Unit, 64, HashMap::new(), HashMap::new());
        let entry = context.new_label();
        context.start_block(entry);
        let scalar = emit_i64_const(&mut context, -1);
        let source_int = emit_int_from_u64(&mut context, scalar);
        context.finish_current(Terminator::Return(Some(source_int)));
        assert!(matches!(
            context.blocks[0].instrs.last(),
            Some(Instr::IntFromU64 { dest, value })
                if *dest == source_int && *value == scalar
        ));
    }
    #[test]
    fn contextually_typed_integer_quantity_literal_lowers_as_quantity_data() {
        let program =
            parse("seiyaku QuantityLiteral { view fn amount() authorize(anyone) -> quantity { return 1; } }")
                .expect("parse quantity literal contract");
        let typed = analyze(&program).expect("analyze contextual quantity literal");
        let lowered = lower(&typed).expect("lower contextual quantity literal");
        let amount = lowered
            .functions
            .iter()
            .find(|function| function.name == "amount")
            .expect("lowered amount function");
        let data_refs = amount
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| match instruction {
                Instr::DataRef { kind, value, .. } => Some((*kind, value.as_str())),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            data_refs.contains(&(DataRefKind::Quantity, "1")),
            "contextual integer must use the canonical quantity pointer kind: {data_refs:?}"
        );
        assert!(!data_refs.contains(&(DataRefKind::Int, "1")));
    }
    #[test]
    fn scalar_and_tuple_state_keys_share_the_canonical_state_record_codec() {
        for ty in [
            Type::Bool,
            Type::Int,
            Type::Decimal,
            Type::Quantity,
            Type::Tuple(vec![Type::AccountId, Type::Int]),
        ] {
            assert!(state_map_key_type(&ty).is_some());
            let mut context = LowerCtx::new(Type::Unit, 64, HashMap::new(), HashMap::new());
            let entry = context.new_label();
            context.start_block(entry);
            let key = emit_i64_const(&mut context, 8);
            let _ = build_state_map_path(&mut context, "values", key, &ty);
            let blob = emit_i64_const(&mut context, 16);
            let decoded =
                decode_state_map_key(&mut context, blob, &ty).expect("canonical key decodes");
            context.finish_current(Terminator::Return(Some(decoded)));
            let instructions = &context.blocks[0].instrs;
            assert!(
                instructions
                    .iter()
                    .any(|instruction| matches!(instruction, Instr::StateValueEncode { .. }))
            );
            assert!(instructions.iter().any(|instruction| matches!(instruction, Instr::DirectHelperSyscall { syscall, .. } if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE)));
            assert!(instructions.iter().all(|instruction| !matches!(
                instruction,
                Instr::PointerToNorito { .. } | Instr::PointerFromNorito { .. }
            )));
        }
    }
    #[test]
    fn direct_syscall_lowering_is_exhaustively_registry_driven_and_fail_closed() {
        for (builtin, spec) in Builtin::registry() {
            let selected = std::panic::catch_unwind(|| direct_builtin_syscall(builtin));
            match spec.lowering {
                BuiltinLowering::DirectSyscall => {
                    assert_eq!(
                        Some(selected.expect("direct builtin must select a syscall")),
                        spec.syscall
                    );
                }
                BuiltinLowering::Instructions | BuiltinLowering::DerivedSyscalls => {
                    assert!(
                        selected.is_err(),
                        "non-direct builtin {} selected an undeclared direct syscall",
                        spec.name
                    );
                }
            }
        }
    }
    #[test]
    fn lower_simple_function() {
        let src = "fn add(int a, int b) { let c = a + b; }";
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        assert_eq!(ir.functions.len(), 1);
        let f = &ir.functions[0];
        assert_eq!(f.blocks.len(), 1); // only entry block
    }
    #[test]
    fn mixed_calls_evaluate_in_source_order_and_permute_only_temp_references() {
        let src = include_str!("ir/fixtures/v1/i001.ko");
        let typed = analyze(&parse(src).expect("parse named call")).expect("analyze named call");
        let ir = lower(&typed).expect("lower named call");
        let run = ir
            .functions
            .iter()
            .find(|function| function.name == "run")
            .expect("run function");
        let calls = run
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .filter_map(|instruction| match instruction {
                Instr::Call { callee, args, dest } => {
                    Some((callee.as_str(), args.as_slice(), *dest))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            calls
                .iter()
                .map(|(callee, _, _)| *callee)
                .collect::<Vec<_>>(),
            ["initial", "second", "first", "combine"]
        );
        let initial = calls[0].2.expect("initial returns a value");
        let second = calls[1].2.expect("second returns a value");
        let first = calls[2].2.expect("first returns a value");
        assert_eq!(calls[3].1, [initial, first, second]);
    }
    #[test]
    fn named_list_intrinsic_evaluates_source_order_before_abi_slots() {
        let source = include_str!("ir/fixtures/v1/i002.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse named List intrinsic"))
                .expect("analyze named List intrinsic"),
        )
        .expect("lower named List intrinsic");
        let mutate = lowered
            .functions
            .iter()
            .find(|function| function.name == "mutate")
            .expect("mutate function");
        let calls = mutate
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .filter_map(|instruction| match instruction {
                Instr::Call { callee, .. } => Some(callee.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(calls, ["replacement", "index"]);
    }
    #[test]
    fn named_quantity_intrinsic_evaluates_dynamic_arguments_in_source_order() {
        let source = include_str!("ir/fixtures/v1/i003.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse named quantity intrinsic"))
                .expect("analyze named quantity intrinsic"),
        )
        .expect("lower named quantity intrinsic");
        let rounded = lowered
            .functions
            .iter()
            .find(|function| function.name == "rounded")
            .expect("rounded function");
        let calls = rounded
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .filter_map(|instruction| match instruction {
                Instr::Call { callee, .. } => Some(callee.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(calls, ["scale", "divisor"]);
    }
    #[test]
    fn require_lowers_declared_error_code_into_abort_ir() {
        let src = include_str!("ir/fixtures/v1/i004.ko");
        let prog = parse(src).expect("parse error enum");
        let typed = analyze(&prog).expect("analyze stable require");
        let ir = lower(&typed).expect("lower stable require");
        let function = &ir.functions[0];
        let mut constants = HashMap::new();
        let mut abort_code = None;
        for block in &function.blocks {
            for instruction in &block.instrs {
                match instruction {
                    Instr::Const { dest, value } => {
                        constants.insert(*dest, *value);
                    }
                    Instr::AbortIf { code, .. } => abort_code = Some(*code),
                    _ => {}
                }
            }
        }
        let abort_code = abort_code.expect("require must lower to AbortIf");
        assert_eq!(constants.get(&abort_code), Some(&1001));
    }
    #[test]
    fn entrypoint_reads_only_the_prepared_host_argument_table() {
        let program = parse(include_str!("ir/fixtures/v1/i005.ko")).unwrap();
        let typed = analyze(&program).unwrap();
        let lowered = lower_with_cap(&typed, 2).unwrap();
        let wrapper = lowered
            .functions
            .iter()
            .find(|function| function.name == "run")
            .unwrap();
        let instructions = wrapper
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::LoadVar { .. }))
        );
        assert!(
            !instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::GetTriggerEvent { .. }))
        );
        assert!(
            !instructions.iter().any(|instruction| matches!(
                instruction,
                Instr::StateGet { .. }
                    | Instr::StateSet { .. }
                    | Instr::StateDel { .. }
                    | Instr::JsonDecode { .. }
            )),
            "public wrappers must not have an alternative test-state decoding path"
        );
    }
    #[test]
    fn single_json_entrypoint_uses_the_same_prepared_argument_table() {
        let src = include_str!("ir/fixtures/v1/i006.ko");
        let prog = parse(src).expect("parse single json entrypoint");
        let typed = analyze(&prog).expect("analyze single json entrypoint");
        let ir = lower_with_cap(&typed, 2).expect("lower single json entrypoint");
        let wrapper = ir
            .functions
            .iter()
            .find(|function| function.name == "run")
            .expect("wrapper function");
        let mut saw_get_trigger = false;
        let mut record_decodes = 0;
        let mut json_field_getters = 0;
        for block in &wrapper.blocks {
            for instr in &block.instrs {
                match instr {
                    Instr::GetTriggerEvent { .. } => saw_get_trigger = true,
                    Instr::DirectHelperSyscall { syscall, .. }
                        if *syscall == ivm_abi::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD =>
                    {
                        record_decodes += 1;
                    }
                    Instr::JsonGetJson { .. } => json_field_getters += 1,
                    _ => {}
                }
            }
        }
        assert!(
            !saw_get_trigger,
            "entrypoint receives already validated table words"
        );
        assert_eq!(
            record_decodes, 0,
            "host decodes the canonical record before entry"
        );
        assert_eq!(
            json_field_getters, 0,
            "the wrapper must not decode the transport JSON per parameter"
        );
    }
    #[test]
    fn recovery_syscalls_lower_generation_as_checked_unsigned_scalar() {
        let source = include_str!(
            "ir/test_sources/recovery_syscalls_lower_generation_as_checked_unsigned_scalar_1.ko"
        );
        let program = parse(source).expect("parse native recovery generation fixture");
        let typed = analyze(&program).expect("analyze native recovery generation fixture");
        let ir = lower(&typed).expect("lower native recovery generation fixture");
        let instructions = ir
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let checked_scalars = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::IntToU64 { dest, .. } => Some(*dest),
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>();
        let recovery_calls = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::DirectHelperSyscall { syscall, args, .. }
                    if matches!(
                        *syscall,
                        ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_PROPOSE
                            | ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_APPROVE
                            | ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_CANCEL
                            | ivm_abi::syscalls::SYSCALL_ACCOUNT_RECOVERY_FINALIZE
                    ) =>
                {
                    Some((*syscall, args))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(recovery_calls.len(), 4);
        for (syscall, args) in recovery_calls {
            assert!(
                checked_scalars.contains(args.last().expect("explicit request generation")),
                "recovery syscall {syscall:#x} must receive a checked u64, not an int handle"
            );
        }
    }
    include!("ir/tests/public_argument_record_abi.rs");
    #[test]
    fn nested_aggregate_returns_use_every_flattened_abi_word() {
        let src = include_str!("ir/fixtures/v1/i007.ko");
        let program = parse(src).expect("parse nested aggregate return");
        let typed = analyze(&program).expect("analyze nested aggregate return");
        let ir = lower(&typed).expect("lower nested aggregate return");
        for name in ["make", "inspect"] {
            let function = ir
                .functions
                .iter()
                .find(|function| function.name == name)
                .unwrap_or_else(|| panic!("missing function `{name}`"));
            assert!(
                function
                    .blocks
                    .iter()
                    .any(|block| matches!(&block.terminator, Terminator::Return(Some(_)))),
                "`{name}` must return one active-only sum handle"
            );
        }
        let implementation = ir
            .functions
            .iter()
            .find(|function| function.name == "inspect")
            .expect("direct entrypoint implementation");
        assert!(implementation.blocks.iter().any(|block| {
            block.instrs.iter().any(|instruction| {
                matches!(
                    instruction,
                    Instr::CallMulti { callee, dests, .. }
                        if callee == "make" && dests.len() == 1
                )
            })
        }));
    }
    #[test]
    fn inactive_sum_has_no_payload_construction_or_store() {
        let source = include_str!("ir/fixtures/v1/i008.ko");
        let program = parse(source).expect("parse active-only Option");
        let typed = analyze(&program).expect("analyze active-only Option");
        let ir = lower(&typed).expect("lower active-only Option");
        let implementation = ir
            .functions
            .iter()
            .find(|function| function.name == "inspect")
            .expect("view implementation");
        assert!(implementation.blocks.iter().all(|block| {
            block.instrs.iter().all(|instruction| {
                !matches!(instruction, Instr::Call { callee, .. } if callee == "poison")
            })
        }));
        let stores = implementation
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| match instruction {
                Instr::Store64Imm { imm, .. } => Some(*imm),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(stores, vec![0], "Option::none writes only its tag");
        assert!(
            implementation
                .blocks
                .iter()
                .any(|block| { matches!(&block.terminator, Terminator::Return(Some(_))) })
        );
    }
    #[test]
    fn tail_expression_lowers_identically_to_explicit_return() {
        let tail = lower(
            &analyze(&parse("fn identity(int value) -> int { value }").expect("parse tail"))
                .expect("analyze tail"),
        )
        .expect("lower tail");
        let explicit = lower(
            &analyze(
                &parse("fn identity(int value) -> int { return value; }").expect("parse return"),
            )
            .expect("analyze return"),
        )
        .expect("lower return");
        fn reachable_blocks(function: &Function) -> Vec<&BasicBlock> {
            let mut pending = vec![function.entry];
            let mut reachable = BTreeSet::new();
            while let Some(label) = pending.pop() {
                if !reachable.insert(label.0) {
                    continue;
                }
                let block = function
                    .blocks
                    .iter()
                    .find(|block| block.label == label)
                    .expect("terminator target must exist");
                match block.terminator {
                    Terminator::Jump(target) => pending.push(target),
                    Terminator::Branch {
                        then_bb, else_bb, ..
                    } => {
                        pending.push(then_bb);
                        pending.push(else_bb);
                    }
                    Terminator::Return(_) | Terminator::Return2(_, _) | Terminator::ReturnN(_) => {}
                }
            }
            function
                .blocks
                .iter()
                .filter(|block| reachable.contains(&block.label.0))
                .collect()
        }
        assert_eq!(
            reachable_blocks(&tail.functions[0]),
            reachable_blocks(&explicit.functions[0]),
            "tail-expression sugar must add no reachable runtime work"
        );
    }
    #[test]
    fn exhaustive_match_reads_only_the_selected_sum_payload() {
        let source = include_str!("ir/fixtures/v1/i009.ko");
        let lowered = lower(&analyze(&parse(source).expect("parse match")).expect("analyze match"))
            .expect("lower match");
        let instructions = lowered.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| matches!(instruction, Instr::Load64Imm { imm: 0, .. }))
                .count(),
            1,
            "match reads the discriminant once"
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| matches!(instruction, Instr::Load64Imm { imm: 8, .. }))
                .count(),
            1,
            "only the payload-bearing arm reads offset 8"
        );
    }
    #[test]
    fn exhaustive_result_match_reads_only_the_selected_sum_payload() {
        let source = include_str!("ir/fixtures/v1/i010.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse Result match")).expect("analyze Result match"),
        )
        .expect("lower Result match");
        let function = &lowered.functions[0];
        let entry = function
            .blocks
            .iter()
            .find(|block| block.label == function.entry)
            .expect("Result match entry block");
        let (ok_label, err_label) = match entry.terminator {
            Terminator::Branch {
                then_bb, else_bb, ..
            } => (then_bb, else_bb),
            _ => panic!("Result match entry must branch on the discriminant"),
        };
        let payload_offsets = |label| {
            function
                .blocks
                .iter()
                .find(|block| block.label == label)
                .expect("Result match arm block")
                .instrs
                .iter()
                .filter_map(|instruction| match instruction {
                    Instr::Load64Imm { imm, .. } => Some(*imm),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            entry
                .instrs
                .iter()
                .filter_map(|instruction| match instruction {
                    Instr::Load64Imm { imm, .. } => Some(*imm),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [0],
            "Result match reads only the discriminant before selecting an arm"
        );
        assert_eq!(
            payload_offsets(ok_label),
            [8],
            "the selected ok arm reads only its scalar payload"
        );
        assert_eq!(
            payload_offsets(err_label),
            [8, 16],
            "the selected err arm reads only its pair payload"
        );
    }
    #[test]
    fn propagation_returns_original_error_handle_without_conversion() {
        let source = include_str!("ir/fixtures/v1/i011.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse propagation")).expect("analyze propagation"),
        )
        .expect("lower propagation");
        let function = &lowered.functions[0];
        assert_eq!(
            function
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, Terminator::Return(Some(_))))
                .count(),
            2,
            "error and success paths return independently"
        );
        assert_eq!(
            function
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter(|instruction| matches!(instruction, Instr::Alloc { .. }))
                .count(),
            1,
            "the propagated error reuses its handle; only Result::ok allocates"
        );
    }
    #[test]
    fn propagation_reallocates_failure_when_the_success_layout_changes() {
        fn memory_profile(function: &Function) -> (usize, usize, usize) {
            let instructions = function.blocks.iter().flat_map(|block| block.instrs.iter());
            instructions.fold((0, 0, 0), |mut counts, instruction| {
                match instruction {
                    Instr::Alloc { .. } => counts.0 += 1,
                    Instr::Load64Imm { .. } => counts.1 += 1,
                    Instr::Store64Imm { .. } => counts.2 += 1,
                    _ => {}
                }
                counts
            })
        }
        let propagated = include_str!("ir/fixtures/v1/i012.ko");
        let explicit = include_str!("ir/fixtures/v1/i013.ko");
        let propagated = lower(
            &analyze(&parse(propagated).expect("parse propagation")).expect("analyze propagation"),
        )
        .expect("lower propagation");
        let explicit = lower(
            &analyze(&parse(explicit).expect("parse explicit match"))
                .expect("analyze explicit match"),
        )
        .expect("lower explicit match");
        assert_eq!(
            propagated.functions[0], explicit.functions[0],
            "postfix Result propagation and its canonical exhaustive match must share exact IR"
        );
        assert_eq!(
            memory_profile(&propagated.functions[0]),
            memory_profile(&explicit.functions[0]),
            "`?` must have the same allocation/load/store profile as the canonical explicit match"
        );
        assert_eq!(
            memory_profile(&propagated.functions[0]).0,
            2,
            "the widened error and success paths each allocate the destination layout once"
        );
        let option = include_str!("ir/fixtures/v1/i014.ko");
        let explicit_option = include_str!("ir/fixtures/v1/i015.ko");
        let option = lower(
            &analyze(&parse(option).expect("parse Option propagation"))
                .expect("analyze Option propagation"),
        )
        .expect("lower Option propagation");
        let explicit_option = lower(
            &analyze(&parse(explicit_option).expect("parse explicit Option match"))
                .expect("analyze explicit Option match"),
        )
        .expect("lower explicit Option match");
        assert_eq!(
            option.functions[0], explicit_option.functions[0],
            "postfix Option propagation and its canonical exhaustive match must share exact IR"
        );
        assert_eq!(
            memory_profile(&option.functions[0]).0,
            2,
            "a widened Option::none must reserve the destination layout"
        );
    }
    #[test]
    fn typed_query_page_lowers_to_one_host_call_and_two_typed_handles() {
        let source = include_str!("ir/fixtures/v1/i016.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse typed query page"))
                .expect("analyze typed query page"),
        )
        .expect("lower typed query page");
        let function = lowered
            .functions
            .iter()
            .find(|function| function.name == "page")
            .expect("page function");
        let pages = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| match instruction {
                Instr::CoreQueryPage {
                    items_dest,
                    next_offset_dest,
                    entity,
                    offset,
                    limit,
                    ..
                } => Some((*items_dest, *next_offset_dest, *entity, *offset, *limit)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(pages.len(), 1, "one source page performs one host query");
        assert_eq!(
            pages[0].2,
            ivm_abi::core_query::CoreQueryEntityTagV1::Account
        );
        assert_eq!(
            function
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter(|instruction| {
                    matches!(instruction, Instr::IntToI64 { dest, .. } if *dest == pages[0].3)
                })
                .count(),
            1,
            "dynamic page offsets cross the existing signed i64 host boundary exactly once"
        );
        assert_eq!(
            function
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter(|instruction| {
                    matches!(instruction, Instr::IntToU64 { dest, .. } if *dest == pages[0].4)
                })
                .count(),
            1,
            "dynamic page limits cross the unsigned bounded host boundary exactly once"
        );
        assert!(function.blocks.iter().any(|block| {
            block.instrs.iter().any(|instruction| {
                matches!(
                    instruction,
                    Instr::TuplePack { items, .. }
                        if items.as_slice() == [pages[0].0, pages[0].1]
                )
            })
        }));
        assert!(
            function
                .blocks
                .iter()
                .any(|block| { matches!(block.terminator, Terminator::Return2(_, _)) })
        );
        let singular = lowered
            .functions
            .iter()
            .find(|function| function.name == "account")
            .expect("account function");
        assert_eq!(
            singular
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter(|instruction| {
                    matches!(
                        instruction,
                        Instr::CoreQueryGet {
                            entity: ivm_abi::core_query::CoreQueryEntityTagV1::Account,
                            ..
                        }
                    )
                })
                .count(),
            1,
            "one singular source query performs one typed host query"
        );
        assert!(
            singular
                .blocks
                .iter()
                .any(|block| { matches!(block.terminator, Terminator::Return(Some(_))) })
        );
    }
    #[test]
    fn native_json_lowers_to_one_schema_bound_build_and_one_word_table() {
        let source = include_str!("ir/fixtures/v1/i017.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse native JSON")).expect("analyze native JSON"),
        )
        .expect("lower native JSON");
        let function = lowered
            .functions
            .iter()
            .find(|function| function.name == "build")
            .expect("build function");
        let instructions = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let builds = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::DirectHelperSyscall {
                    syscall,
                    args,
                    dest,
                } if *syscall == ivm_abi::syscalls::SYSCALL_JSON_BUILD => {
                    Some((*dest, args.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            builds.len(),
            1,
            "native JSON performs exactly one host build"
        );
        let [schema_ref, table, word_count] = builds[0].1.as_slice() else {
            panic!("JSON_BUILD must receive schema, word table, and word count");
        };
        let encoded_schema = instructions
            .iter()
            .find_map(|instruction| match instruction {
                Instr::DataRef {
                    dest,
                    kind: DataRefKind::NoritoBytes,
                    value,
                } if dest == schema_ref => value.strip_prefix("0x"),
                _ => None,
            })
            .expect("static JSON construction schema");
        let schema_bytes = hex::decode(encoded_schema).expect("schema hex");
        let schema: ivm_abi::json::JsonConstructionSchemaV1 =
            norito::decode_from_bytes(&schema_bytes).expect("decode construction schema");
        assert!(schema.validate());
        assert_eq!(schema.word_count(), Some(6));
        assert!(matches!(
            &schema.nodes[0],
            ivm_abi::json::JsonConstructionNodeV1::Object { keys }
                if keys.iter().map(String::as_str).eq([
                    "owner", "amount", "primary", "labels", "maybe"
                ])
        ));
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| {
                    matches!(instruction, Instr::Store64Imm { base, .. } if base == table)
                })
                .count(),
            6,
            "every schema word is written once into one contiguous table"
        );
        assert!(instructions.iter().any(|instruction| {
            matches!(instruction, Instr::Const { dest, value: 6 } if dest == word_count)
        }));
        assert!(
            instructions
                .iter()
                .all(|instruction| !matches!(instruction, Instr::JsonObject { .. }))
        );
    }
    #[test]
    fn list_layout_flattens_nested_sum_handles_to_one_word() {
        let nested = Type::List(
            Box::new(Type::Option(Box::new(Type::Result(
                Box::new(Type::Quantity),
                Box::new(Type::Bool),
            )))),
            64,
        );
        let (element, layout) = list_layout_for_type(&nested).expect("valid nested List layout");
        assert!(matches!(element, Type::Option(_)));
        assert_eq!(layout.capacity(), 64);
        assert_eq!(layout.element_words(), 1);
        assert_eq!(layout.allocation_bytes(), Ok((2 + 64) * 8));
        let enumerated = Type::List(Box::new(Type::Tuple(vec![Type::Int, Type::Quantity])), 4);
        let (_, layout) = list_layout_for_type(&enumerated).expect("pair List layout");
        assert_eq!(layout.element_words(), 2);
    }
    #[test]
    fn list_len_and_enumerate_materialize_source_int_values() {
        let source = "fn indices() -> List<(int, int), 4> {\
                 let List<int, 4> values = [1, 2];\
                 let length = values.len();\
                 values.enumerate()\
             }";
        let lowered = lower(
            &analyze(&parse(source).expect("parse List scalar boundaries"))
                .expect("analyze List scalar boundaries"),
        )
        .expect("lower List scalar boundaries");
        let instructions = lowered.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let materialized = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::IntFromU64 { dest, value } => Some((*dest, *value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            materialized.len() >= 2,
            "List.len and List.enumerate indices must each cross the scalar/int boundary"
        );
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                Instr::TuplePack { items, .. }
                    if materialized.iter().any(|(source_int, _)| items.first() == Some(source_int))
            )
        }));
    }
    #[test]
    fn list_get_converts_an_arbitrary_width_index_only_after_bounds_proof() {
        let source =
            "fn probe(List<int, 4> values, int index) -> Option<int> { values.get(index) }";
        let lowered = lower(
            &analyze(&parse(source).expect("parse List.get bounds proof"))
                .expect("analyze List.get bounds proof"),
        )
        .expect("lower List.get bounds proof");
        let function = &lowered.functions[0];
        let conversion_block = function
            .blocks
            .iter()
            .find(|block| {
                block
                    .instrs
                    .iter()
                    .any(|instruction| matches!(instruction, Instr::IntToU64 { .. }))
            })
            .expect("successful List.get arm converts its proven index");
        let predecessor = function
            .blocks
            .iter()
            .find(|block| {
                matches!(
                    block.terminator,
                    Terminator::Branch { then_bb, .. } if then_bb == conversion_block.label
                )
            })
            .expect("bounds-check branch dominates scalar conversion");
        assert!(predecessor.instrs.iter().any(|instruction| {
            matches!(
                instruction,
                Instr::NumericCompare {
                    op: BinaryOp::Ge,
                    kind: WideNumericKind::Int,
                    ..
                }
            )
        }));
        assert!(predecessor.instrs.iter().any(|instruction| {
            matches!(
                instruction,
                Instr::NumericCompare {
                    op: BinaryOp::Lt,
                    kind: WideNumericKind::Int,
                    ..
                }
            )
        }));
        assert!(
            predecessor
                .instrs
                .iter()
                .all(|instruction| !matches!(instruction, Instr::IntToU64 { .. })),
            "out-of-range indices must reach Option::none without a narrowing fault"
        );
    }
    #[test]
    fn scalar_protocol_arguments_use_checked_adaptive_int_conversion() {
        let source = include_str!("ir/fixtures/v1/i018.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse checked scalar boundaries"))
                .expect("analyze checked scalar boundaries"),
        )
        .expect("lower checked scalar boundaries");
        let instructions = lowered.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let converted = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::IntToU64 { dest, .. } => Some(*dest),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(converted.len(), 2);
        for scalar in instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::Sm4CcmSeal {
                    tag_len: Some(tag_len),
                    ..
                } => Some(*tag_len),
                Instr::SetAccountQuorum { quorum, .. } => Some(*quorum),
                _ => None,
            })
        {
            assert!(
                converted.contains(&scalar),
                "scalar protocol register must receive a checked u64 conversion"
            );
        }
    }
    #[test]
    fn scalar_protocol_literals_outside_u64_fail_lowering() {
        for value in ["-1", "18446744073709551616"] {
            let source = format!(
                "fn seal(bytes payload) {{ let _sealed = crypto::sm4_ccm::seal(\
                    key: payload, nonce: payload, aad: payload, payload: payload, tag_length: {value}); }}"
            );
            let typed = analyze(&parse(&source).expect("parse scalar boundary overflow"))
                .expect("analyze scalar boundary overflow");
            let error = lower(&typed).expect_err("out-of-range scalar argument must fail closed");
            assert!(
                error.contains("outside the unsigned 64-bit range required by this host boundary"),
                "unexpected error for {value}: {error}"
            );
        }
    }
    #[test]
    fn state_map_int_keys_use_the_canonical_state_record() {
        let source = "state StateMap<int, int> balances; fn set(int key, int value) { balances[key] = value; }";
        let lowered = lower(
            &analyze(&parse(source).expect("parse numeric StateMap key"))
                .expect("analyze numeric StateMap key"),
        )
        .expect("lower numeric StateMap key");
        let instructions = lowered.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let path_keys = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::PathMapKeyNorito { key_blob, .. } => Some(*key_blob),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(path_keys.len(), 1, "one canonical key per access");
        let encoded_keys = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::StateValueEncode { dest, words, .. } if *dest == path_keys[0] => {
                    Some(words.as_slice())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            encoded_keys.len(),
            1,
            "one canonical key encoding per access"
        );
        assert_eq!(encoded_keys[0].len(), 1, "int keys retain one typed word");
        assert!(
            !instructions
                .iter()
                .any(|instruction| { matches!(instruction, Instr::PointerToNorito { .. }) }),
            "scalar keys must not retain the old scalar-envelope path"
        );
    }
    #[test]
    fn scalar_state_paths_lower_to_framed_state_path_bytes() {
        let source = include_str!("ir/fixtures/v1/i019.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse scalar durable state"))
                .expect("analyze scalar durable state"),
        )
        .expect("lower scalar durable state");
        let instructions = lowered
            .functions
            .iter()
            .find(|function| function.name == "read")
            .expect("read function")
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let path = instructions
            .iter()
            .find_map(|instruction| match instruction {
                Instr::StateGet { path, .. } => Some(*path),
                _ => None,
            })
            .expect("scalar read must emit STATE_GET");
        let raw = instructions
            .iter()
            .find_map(|instruction| match instruction {
                Instr::DataRef {
                    dest,
                    kind: DataRefKind::NoritoBytes,
                    value,
                } if *dest == path => Some(value),
                _ => None,
            })
            .expect("STATE_GET path must originate from NoritoBytes");
        let encoded = hex::decode(raw.strip_prefix("0x").expect("hex StatePath literal"))
            .expect("decode StatePath literal");
        let decoded: StatePath =
            ivm_abi::codec::decode_canonical_norito(&encoded).expect("decode StatePath");
        assert_eq!(decoded.as_ref(), "counter");
        assert!(instructions.iter().all(|instruction| {
            !matches!(
                instruction,
                Instr::DataRef {
                    dest,
                    kind: DataRefKind::Name,
                    ..
                } if *dest == path
            )
        }));
    }
    #[test]
    fn list_literal_and_comprehension_use_only_contiguous_ir_operations() {
        let source = include_str!("ir/fixtures/v1/i020.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse List comprehension"))
                .expect("analyze List comprehension"),
        )
        .expect("lower List comprehension");
        let instructions = lowered.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| matches!(instruction, Instr::Alloc { .. }))
                .count(),
            2,
            "literal and result each use one contiguous allocation"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::Load64 { .. }))
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::Store64 { .. }))
        );
        assert!(instructions.iter().all(|instruction| {
            !matches!(instruction, Instr::Call { callee, .. } if callee.contains("list"))
        }));
    }
    #[test]
    fn identity_comprehension_does_not_exceed_bounded_copy_baseline() {
        fn instruction_count(source: &str) -> usize {
            lower(
                &analyze(&parse(source).expect("parse bounded copy"))
                    .expect("analyze bounded copy"),
            )
            .expect("lower bounded copy")
            .functions[0]
                .blocks
                .iter()
                .map(|block| block.instrs.len() + 1)
                .sum()
        }
        let comprehension = instruction_count(
            "fn copy() -> List<int, 4> { let List<int, 4> source = [1, 2]; [value for value in source] }",
        );
        let bounded_baseline = instruction_count(
            "fn copy() -> List<int, 4> { let List<int, 4> source = [1, 2]; source.take(4) }",
        );
        assert!(
            comprehension <= bounded_baseline,
            "identity List sugar emitted {comprehension} operations versus {bounded_baseline} for the bounded copy baseline"
        );
    }
    #[test]
    fn every_list_method_lowers_without_runtime_helper_calls() {
        let source = include_str!("ir/fixtures/v1/i021.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse List methods")).expect("analyze List methods"),
        )
        .expect("lower List methods");
        let instructions = lowered.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert!(instructions.iter().all(|instruction| {
            !matches!(instruction, Instr::Call { callee, .. } if callee.starts_with("__kotodama_list_"))
        }));
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::Alloc { .. }))
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::Load64Imm { imm: 0, .. }))
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::Store64Imm { imm: 0, .. }))
        );
    }
    #[test]
    fn list_take_zero_lowers_to_a_bounded_empty_copy() {
        let source =
            "fn empty() -> List<int, 1> { let List<int, 4> values = [1, 2]; values.take(0) }";
        let lowered = lower(
            &analyze(&parse(source).expect("parse List.take(0)")).expect("analyze List.take(0)"),
        )
        .expect("lower List.take(0)");
        let function = &lowered.functions[0];
        assert!(
            function
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .any(|instruction| matches!(instruction, Instr::Const { value: 0, .. })),
            "the zero limit must remain an explicit deterministic bound"
        );
        assert!(function.blocks.iter().all(|block| {
            block.instrs.iter().all(|instruction| {
                !matches!(instruction, Instr::Call { callee, .. } if callee.starts_with("__kotodama_list_"))
            })
        }));
    }
    #[test]
    fn recursive_list_contains_dereferences_aggregate_handles() {
        let source = include_str!("ir/fixtures/v1/i022.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse recursive List.contains"))
                .expect("analyze recursive List.contains"),
        )
        .expect("lower recursive List.contains");
        let function = &lowered.functions[0];
        let instructions = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .all(|instruction| !matches!(instruction, Instr::PointerEq { .. })),
            "compiler-owned aggregate handles must never be compared by pointer identity"
        );
        assert!(
            instructions
                .iter()
                .filter(|instruction| matches!(instruction, Instr::Load64Imm { imm: 0, .. }))
                .count()
                >= 5,
            "nested List lengths and active sum tags must be loaded structurally"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instr::TupleGet { .. })),
            "struct and tuple fields must be compared structurally"
        );
        assert!(
            function
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, Terminator::Branch { .. }))
                .count()
                >= 6,
            "sum tags and nested List bounds must guard active payload reads"
        );
    }
    #[test]
    fn multiword_failed_list_mutation_branches_have_no_stores_or_allocations() {
        let source = include_str!("ir/fixtures/v1/i023.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse failed mutation paths"))
                .expect("analyze failed mutation paths"),
        )
        .expect("lower failed mutation paths");
        for function in &lowered.functions {
            let (success_label, failure_label) = function
                .blocks
                .iter()
                .find_map(|block| match block.terminator {
                    Terminator::Branch {
                        then_bb, else_bb, ..
                    } => {
                        let success = function
                            .blocks
                            .iter()
                            .find(|candidate| candidate.label == then_bb)
                            .expect("mutation success block exists");
                        success
                            .instrs
                            .iter()
                            .any(|instruction| {
                                matches!(
                                    instruction,
                                    Instr::Store64 { .. } | Instr::Store64Imm { .. }
                                )
                            })
                            .then_some((then_bb, else_bb))
                    }
                    _ => None,
                })
                .expect("mutation has a bounds branch");
            let success = function
                .blocks
                .iter()
                .find(|block| block.label == success_label)
                .expect("mutation success block exists");
            let expected_store_count = if function.name == "set" { 2 } else { 3 };
            assert_eq!(
                success
                    .instrs
                    .iter()
                    .filter(|instruction| matches!(
                        instruction,
                        Instr::Store64 { .. } | Instr::Store64Imm { .. }
                    ))
                    .count(),
                expected_store_count,
                "{} must write both Pair words{} only on success",
                function.name,
                if function.name == "push" {
                    " and then commit the length"
                } else {
                    ""
                }
            );
            let failure = function
                .blocks
                .iter()
                .find(|block| block.label == failure_label)
                .expect("failure block exists");
            assert!(
                failure.instrs.iter().all(|instruction| !matches!(
                    instruction,
                    Instr::Alloc { .. } | Instr::Store64 { .. } | Instr::Store64Imm { .. }
                )),
                "{} failure block must be allocation- and store-free: {:?}",
                function.name,
                failure.instrs
            );
        }
    }
    #[test]
    fn entrypoint_list_schema_is_recursive_and_capacity_bound() {
        use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;
        let ty = Type::List(Box::new(Type::Option(Box::new(Type::Quantity))), 64);
        let schema = entrypoint_return_schema("items", Some(&ty))
            .expect("build List return schema")
            .expect("non-unit return schema");
        let [Node::List(list), Node::Option, Node::Leaf(_)] = schema.nodes.as_slice() else {
            panic!("expected one flat List<Option<quantity>> preorder tape");
        };
        assert_eq!(list.capacity, 64);
        assert_eq!(schema.word_count(), Some(1));
    }
    #[test]
    fn query_page_entrypoint_schemas_are_structural_and_roundtrip_for_all_views() {
        use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;
        let source = include_str!("ir/fixtures/v1/i024.ko");
        let typed = analyze(&parse(source).expect("parse all typed query pages"))
            .expect("analyze all typed query pages");
        let mut encoded_schemas = BTreeSet::new();
        for (entrypoint_name, view_name) in [
            ("accounts", "AccountView"),
            ("assets", "AssetView"),
            ("asset_definitions", "AssetDefinitionView"),
            ("domains", "DomainView"),
            ("nfts", "NftView"),
        ] {
            let function = typed
                .items
                .iter()
                .map(|item| match item {
                    TypedItem::Function(function) => function,
                })
                .find(|function| function.name == entrypoint_name)
                .unwrap_or_else(|| panic!("missing {entrypoint_name} entrypoint"));
            let schema = entrypoint_return_schema(entrypoint_name, function.ret_ty.as_ref())
                .expect("build structural query-page schema")
                .expect("query page has a public return schema");
            let [
                Node::Struct(page),
                Node::List(items),
                Node::Struct(view),
                ..,
            ] = schema.nodes.as_slice()
            else {
                panic!("unexpected {entrypoint_name} schema: {schema:?}");
            };
            assert_eq!(page.name, "kotodama::QueryPage");
            assert_eq!(page.fields, ["items", "next_offset"]);
            assert_eq!(items.capacity, 64);
            assert_eq!(view.name, format!("kotodama::{view_name}"));
            assert!(matches!(
                schema
                    .nodes
                    .as_slice()
                    .get(schema.nodes.len().saturating_sub(2)..),
                Some([
                    Node::Option,
                    Node::Leaf(ivm_abi::entrypoint::EntrypointValueKindV1::Int)
                ])
            ));
            assert!(schema.validate());
            assert_eq!(schema.word_count(), Some(2));
            let encoded = norito::to_bytes(&schema).expect("encode query-page schema");
            let decoded: ivm_abi::entrypoint::EntrypointValueTypeV1 =
                norito::decode_from_bytes(&encoded).expect("decode query-page schema");
            assert_eq!(decoded, schema);
            assert!(
                encoded_schemas.insert(encoded),
                "{view_name} specialization must have a distinct structural schema"
            );
        }
        assert_eq!(encoded_schemas.len(), 5);
    }
    #[test]
    fn aggregate_argument_words_beyond_thirteen_lower_to_one_table_signature() {
        let source = include_str!("ir/fixtures/v1/i025.ko");
        let program = parse(source).expect("parse wide aggregate call");
        let typed = analyze(&program).expect("analyze wide aggregate call");
        let lowered = lower(&typed).expect("lowering supports bounded call tables");
        assert!(
            lowered
                .functions
                .iter()
                .any(|function| function.params.len() == 14)
        );
    }
    #[test]
    fn invoke_entrypoint_lowers_to_current_caller_host_intrinsic() {
        let program = parse(include_str!("ir/fixtures/v1/i026.ko")).unwrap();
        let typed = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&program)
            .unwrap();
        let ir = lower_with_cap(&typed, 2).unwrap();
        let test = ir
            .functions
            .iter()
            .find(|function| function.name == "drive_run")
            .unwrap();
        let instructions = test
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert!(instructions.iter().any(|instruction| matches!(
            instruction,
            Instr::InvokeEntrypointAs { actor: None, .. }
        )));
        assert!(
            !instructions.iter().any(|instruction| matches!(
                instruction,
                Instr::StateGet { .. }
                    | Instr::StateSet { .. }
                    | Instr::StateDel { .. }
                    | Instr::Call { .. }
            )),
            "public test calls must use canonical host dispatch, with no private state override"
        );
        assert!(
            instructions.iter().any(|instruction| matches!(
                instruction,
                Instr::NumericCompare {
                    op: BinaryOp::Eq,
                    kind: WideNumericKind::Int,
                    ..
                }
            )),
            "numeric assertions compare values, not pointer addresses"
        );
    }
    #[test]
    fn invoke_entrypoint_tuple_return_uses_current_caller_host_intrinsic() {
        let program = parse(include_str!("ir/fixtures/v1/i027.ko")).unwrap();
        let typed = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&program)
            .unwrap();
        let ir = lower_with_cap(&typed, 2).unwrap();
        let test = ir
            .functions
            .iter()
            .find(|function| function.name == "drive_run")
            .unwrap();
        assert!(
            test.blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .any(|instruction| matches!(
                    instruction,
                    Instr::InvokeEntrypointAsMulti { actor: None, .. }
                ))
        );
    }
    #[test]
    fn invoke_entrypoint_as_lowers_to_test_host_intrinsics() {
        let src = include_str!("ir/fixtures/v1/i028.ko");
        let prog = parse(src).expect("parse invoke_entrypoint_as");
        let typed = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&prog)
            .expect("analyze invoke_entrypoint_as");
        let ir = lower_with_cap(&typed, 2).expect("lower invoke_entrypoint_as");
        let test_fn = ir
            .functions
            .iter()
            .find(|function| function.name == "drive_run")
            .expect("test function");
        let mut saw_invoke = false;
        let mut saw_expect_reject = false;
        for block in &test_fn.blocks {
            for instr in &block.instrs {
                match instr {
                    Instr::InvokeEntrypointAs { dest: Some(_), .. } => {
                        saw_invoke = true;
                    }
                    Instr::ExpectRejectAs { .. } => saw_expect_reject = true,
                    _ => {}
                }
            }
        }
        assert!(saw_invoke, "expected InvokeEntrypointAs in lowered test");
        assert!(saw_expect_reject, "expected ExpectRejectAs in lowered test");
    }
    #[test]
    fn test_helper_calls_announce_their_source_site_first() {
        let src = include_str!("ir/fixtures/v1/i052.ko");
        let typed = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&parse(src).expect("parse invoke_entrypoint_as"))
            .expect("analyze invoke_entrypoint_as");
        let ir = lower_with_cap(&typed, 2).expect("lower invoke_entrypoint_as");
        let test_fn = ir
            .functions
            .iter()
            .find(|function| function.name == "drive_run")
            .expect("test function");
        let instructions = test_fn
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let helper_calls = instructions
            .iter()
            .enumerate()
            .filter(|(_, instruction)| {
                matches!(
                    instruction,
                    Instr::InvokeEntrypointAs { .. } | Instr::ExpectRejectAs { .. }
                )
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(helper_calls.len(), 2);
        for index in helper_calls {
            assert!(
                instructions[..index]
                    .iter()
                    .rev()
                    .any(|instruction| matches!(
                        instruction,
                        Instr::DirectHelperSyscall { syscall, args, .. }
                            if *syscall == ivm_abi::syscalls::SYSCALL_KOTO_TEST_CALL_SITE
                                && args.len() == 1
                    )),
                "helper call at {index} has no call-site announcement"
            );
        }
        let announcements = instructions
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction,
                    Instr::DirectHelperSyscall { syscall, .. }
                        if *syscall == ivm_abi::syscalls::SYSCALL_KOTO_TEST_CALL_SITE
                )
            })
            .count();
        assert_eq!(announcements, 2, "one announcement per helper call");
    }
    #[test]
    fn invoke_entrypoint_as_tuple_return_lowers_to_multi_intrinsic() {
        let src = include_str!("ir/fixtures/v1/i029.ko");
        let prog = parse(src).expect("parse tuple invoke_entrypoint_as");
        let typed = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&prog)
            .expect("analyze tuple invoke_entrypoint_as");
        let ir = lower_with_cap(&typed, 2).expect("lower tuple invoke_entrypoint_as");
        let test_fn = ir
            .functions
            .iter()
            .find(|function| function.name == "drive_run")
            .expect("test function");
        let mut saw_multi = false;
        let mut saw_tuple_pack = false;
        for block in &test_fn.blocks {
            for instr in &block.instrs {
                match instr {
                    Instr::InvokeEntrypointAsMulti { dests, .. } => {
                        saw_multi = true;
                        assert_eq!(dests.len(), 2);
                    }
                    Instr::TuplePack { items, .. } if items.len() == 2 => saw_tuple_pack = true,
                    _ => {}
                }
            }
        }
        assert!(
            saw_multi,
            "tuple invoke_entrypoint_as should use multi-return test intrinsic"
        );
        assert!(
            saw_tuple_pack,
            "tuple invoke_entrypoint_as should pack returned values"
        );
    }
    #[test]
    fn actor_helpers_lower_to_test_host_intrinsics() {
        let src = include_str!("ir/fixtures/v1/i030.ko");
        let prog = parse(src).expect("parse actor helpers");
        let typed = semantic::SemanticContext::with_capabilities(false, true)
            .analyze(&prog)
            .expect("analyze actor helpers");
        let ir = lower_with_cap(&typed, 2).expect("lower actor helpers");
        let test_fn = ir
            .functions
            .iter()
            .find(|function| function.name == "drive_helpers")
            .expect("test function");
        let mut saw_actor_account = false;
        let mut saw_actor_public_key = false;
        let mut saw_actor_sign = false;
        for block in &test_fn.blocks {
            for instr in &block.instrs {
                match instr {
                    Instr::ActorAccount { .. } => saw_actor_account = true,
                    Instr::ActorPublicKey { .. } => saw_actor_public_key = true,
                    Instr::ActorSign { .. } => saw_actor_sign = true,
                    _ => {}
                }
            }
        }
        assert!(saw_actor_account, "expected ActorAccount in lowered test");
        assert!(
            saw_actor_public_key,
            "expected ActorPublicKey in lowered test"
        );
        assert!(saw_actor_sign, "expected ActorSign in lowered test");
    }
    #[test]
    fn lower_if() {
        let src = "fn f(int a, int b) { if a == b { let c = a; } else { let c = b; } }";
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        assert_eq!(ir.functions[0].blocks.len(), 4); // entry, then, else, end
    }
    #[test]
    fn conditional_environment_joins_copy_each_arm_to_the_returned_value() {
        let source = r#"
            fn via_if(bool flag, int left, int right) -> int {
                var value = 0;
                if flag { value = left; } else { value = right; }
                return value;
            }
            fn via_if_let(Option<int> input, int fallback) -> int {
                var value = 0;
                if let Option::some(item) = input { value = item; }
                else { value = fallback; }
                return value;
            }
        "#;
        let ir = lower(&analyze(&parse(source).unwrap()).unwrap()).expect("lower both joins");
        assert_eq!(ir.functions.len(), 2);
        for function in &ir.functions {
            let (join_label, returned) = function
                .blocks
                .iter()
                .find_map(|block| {
                    if let Terminator::Return(Some(value)) = block.terminator {
                        Some((block.label, value))
                    } else {
                        None
                    }
                })
                .expect("joined return");
            let sources: Vec<_> = function.blocks.iter().filter(|block| {
                matches!(block.terminator, Terminator::Jump(target) if target == join_label)
            }).map(|block| {
                block.instrs.iter().find_map(|instruction| match instruction {
                    Instr::Copy { dest, src } if *dest == returned => Some(*src),
                    _ => None,
                }).expect("each predecessor initializes the joined value")
            }).collect();
            assert_eq!(
                sources.len(),
                2,
                "{} must retain both predecessors",
                function.name
            );
            assert_ne!(
                sources[0], sources[1],
                "each arm must retain its own source"
            );
        }
    }

    #[test]
    fn logical_operators_lower_to_short_circuit_cfg() {
        let src = include_str!("ir/fixtures/v1/i031.ko");
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower logical operators");
        for (name, short_value, rhs_on_then) in [("both", 0, true), ("either", 1, false)] {
            let function = ir
                .functions
                .iter()
                .find(|function| function.name == name)
                .expect("logical function");
            assert!(
                function
                    .blocks
                    .iter()
                    .all(|block| block.instrs.iter().all(|instr| !matches!(
                        instr,
                        Instr::Binary {
                            op: BinaryOp::And | BinaryOp::Or,
                            ..
                        }
                    ))),
                "{name} must not eagerly evaluate logical operands"
            );
            let rhs_block = function
                .blocks
                .iter()
                .find(|block| {
                    block
                        .instrs
                        .iter()
                        .any(|instr| matches!(instr, Instr::Call { callee, .. } if callee == "rhs"))
                })
                .expect("right-hand-side call block");
            let short_block = function
                .blocks
                .iter()
                .find(|block| {
                    block.instrs.iter().any(|instr| {
                        matches!(instr, Instr::Const { value, .. } if *value == short_value)
                    }) && block
                        .instrs
                        .iter()
                        .any(|instr| matches!(instr, Instr::Copy { .. }))
                })
                .expect("short-circuit result block");
            let entry = function
                .blocks
                .iter()
                .find(|block| block.label == function.entry)
                .expect("entry block");
            let Terminator::Branch {
                then_bb, else_bb, ..
            } = &entry.terminator
            else {
                panic!("{name} entry must branch before evaluating rhs");
            };
            if rhs_on_then {
                assert_eq!(*then_bb, rhs_block.label);
                assert_eq!(*else_bb, short_block.label);
            } else {
                assert_eq!(*then_bb, short_block.label);
                assert_eq!(*else_bb, rhs_block.label);
            }
            let result = function
                .blocks
                .iter()
                .find_map(|block| match &block.terminator {
                    Terminator::Return(Some(result)) => Some(*result),
                    _ => None,
                })
                .expect("logical result return");
            for predecessor in [rhs_block, short_block] {
                assert!(
                    predecessor
                        .instrs
                        .iter()
                        .any(|instr| matches!(instr, Instr::Copy { dest, .. } if *dest == result),),
                    "{name} predecessor must merge into the returned result"
                );
            }
        }
    }
    #[test]
    fn lower_bounded_range_loop() {
        let src = "fn f() { for index in range(2) { let value = index; } }";
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        assert!(ir.functions[0].blocks.len() >= 4);
    }
    #[test]
    fn bounded_loop_only_materializes_live_mutated_phi_slots() {
        let src = include_str!("ir/fixtures/v1/i032.ko");
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let function = &ir.functions[0];
        let entry = function
            .blocks
            .iter()
            .find(|block| block.label == function.entry)
            .expect("entry block");
        let invariant = entry
            .instrs
            .iter()
            .find_map(|instruction| match instruction {
                Instr::DataRef {
                    dest,
                    kind: DataRefKind::Int,
                    value,
                } if value == "7" => Some(*dest),
                _ => None,
            })
            .expect("invariant constant");
        let entry_copies = entry
            .instrs
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::Copy { dest, src } => Some((*dest, *src)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entry_copies.len(),
            2,
            "only the range index and carried accumulator need loop phi slots"
        );
        assert!(
            entry_copies.iter().all(|(_, src)| *src != invariant),
            "an immutable local must not be copied into loop-carried state"
        );
    }
    #[test]
    fn break_and_continue_update_only_selected_loop_phi_slots() {
        let src = include_str!("ir/fixtures/v1/i033.ko");
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let function = &ir.functions[0];
        let entry = function
            .blocks
            .iter()
            .find(|block| block.label == function.entry)
            .expect("entry block");
        let phi_destinations = entry
            .instrs
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::Copy { dest, .. } => Some(*dest),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(phi_destinations.len(), 2);
        assert!(phi_destinations.iter().all(|destination| {
            function
                .blocks
                .iter()
                .flat_map(|block| block.instrs.iter())
                .filter(|instruction| {
                    matches!(instruction, Instr::Copy { dest, .. } if dest == destination)
                })
                .count()
                >= 2
        }));
    }
    #[test]
    fn state_map_foreach_carries_mutated_locals_through_break_and_continue() {
        let src = include_str!("ir/fixtures/v1/i034.ko");
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let function = ir
            .functions
            .iter()
            .find(|function| function.name == "f")
            .expect("foreach function");
        let returned = function
            .blocks
            .iter()
            .find_map(|block| match &block.terminator {
                Terminator::Return(Some(result)) => Some(*result),
                _ => None,
            })
            .expect("returned accumulator");
        assert!(
            function.blocks.iter().flat_map(|block| &block.instrs).any(
                |instruction| matches!(instruction, Instr::Copy { dest, .. } if *dest == returned)
            ),
            "the returned accumulator must be initialized as a loop phi after the page snapshot is materialized"
        );
        assert!(
            function
                .blocks
                .iter()
                .flat_map(|block| block.instrs.iter())
                .filter(|instruction| {
                    matches!(instruction, Instr::Copy { dest, .. } if *dest == returned)
                })
                .count()
                >= 3,
            "normal, break, and continue paths must update the loop accumulator"
        );
    }
    #[test]
    fn state_page_lowering_emits_one_bounded_scan_with_cursor_schema() {
        let source = "const int LIMIT = 2; state StateMap<int, int> Values; fn scan(Option<StateCursor<int>> after) -> StatePage<int, int, 4> { Values.page(after: after, limit: LIMIT * 2) }";
        let typed = analyze(&parse(source).expect("parse typed page")).expect("analyze page");
        let ir = lower(&typed).expect("lower typed page");
        let function = &ir.functions[0];
        let scans = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| {
                if let Instr::StateScan {
                    limit,
                    dynamic_access_hint,
                    ..
                } = instruction
                {
                    Some((*limit, dynamic_access_hint))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].1.bound_kind, "page");
        assert_eq!(scans[0].1.max_keys, 64);
        assert_eq!(scans[0].1.key_type, "int");
        assert!(function.blocks.iter().flat_map(|block| &block.instrs).any(|instruction| matches!(instruction, Instr::Const { dest, value: 4 } if *dest == scans[0].0)));
        let schema = entrypoint_argument_schema(
            typed
                .items
                .iter()
                .find_map(|item| {
                    let TypedItem::Function(function) = item;
                    (function.name == "scan").then_some(function.param_types.as_slice())
                })
                .expect("scan parameters"),
        )
        .expect("cursor argument schema")
        .expect("one cursor parameter");
        assert!(schema.validate());
    }
    #[test]
    fn nested_loops_do_not_carry_outer_invariants() {
        let src = include_str!("ir/fixtures/v1/i035.ko");
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let function = &ir.functions[0];
        let invariant = function
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .find_map(|instruction| match instruction {
                Instr::DataRef {
                    dest,
                    kind: DataRefKind::Int,
                    value,
                } if value == "9" => Some(*dest),
                _ => None,
            })
            .expect("invariant constant");
        assert!(function.blocks.iter().all(|block| {
            block.instrs.iter().all(
                |instruction| !matches!(instruction, Instr::Copy { src, .. } if *src == invariant),
            )
        }));
    }
    #[test]
    fn leaf_identity_ir_has_no_copy_or_stack_pseudo_traffic() {
        let src = "fn identity(int value) -> int { return value; }";
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let function = &ir.functions[0];
        assert_eq!(
            function.blocks.len(),
            2,
            "return creates one sealed dead continuation"
        );
        assert!(function.blocks.iter().any(|block| {
            matches!(block.terminator, Terminator::Jump(target) if target == block.label)
        }));
        assert!(function.blocks.iter().all(|block| {
            block
                .instrs
                .iter()
                .all(|instruction| !matches!(instruction, Instr::Copy { .. }))
        }));
        assert!(function.blocks.iter().any(|block| {
            matches!(block.terminator, Terminator::Return(Some(_)))
                && block
                    .instrs
                    .iter()
                    .all(|instruction| matches!(instruction, Instr::LoadVar { .. }))
        }));
    }
    #[test]
    fn lower_return() {
        let src = "fn f() -> int { return 1; let x = 2; }";
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        // Unreachable source stays in raw lowering IR for budget enforcement,
        // but is sealed so SSA can validate and prune it deterministically.
        let f = &ir.functions[0];
        assert_eq!(f.blocks.len(), 2);
        assert!(
            f.blocks
                .iter()
                .any(|b| matches!(b.terminator, Terminator::Return(_)))
        );
    }
    #[test]
    fn mixed_value_and_divergent_function_tails_have_no_reachable_unit_return() {
        let source = include_str!("ir/fixtures/v1/i036.ko");
        let lowered = lower(
            &analyze(&parse(source).expect("parse mixed flow tails"))
                .expect("analyze mixed flow tails"),
        )
        .expect("lower mixed flow tails");
        for name in ["via_if", "via_if_let", "via_match", "wholly_divergent"] {
            let function = lowered
                .functions
                .iter()
                .find(|function| function.name == name)
                .expect("lowered mixed-flow function");
            assert!(
                function
                    .blocks
                    .iter()
                    .all(|block| !matches!(block.terminator, Terminator::Return(None))),
                "{name} must not retain even an unreachable synthetic unit return"
            );
            let mut pending = vec![function.entry];
            let mut visited = std::collections::HashSet::new();
            let mut reachable_returns = 0_usize;
            while let Some(label) = pending.pop() {
                if !visited.insert(label) {
                    continue;
                }
                let block = function
                    .blocks
                    .iter()
                    .find(|block| block.label == label)
                    .expect("CFG edge references a known block");
                match &block.terminator {
                    Terminator::Return(None) => {
                        panic!("{name} has a reachable unit return at {label:?}")
                    }
                    Terminator::Return(Some(_))
                    | Terminator::Return2(_, _)
                    | Terminator::ReturnN(_) => reachable_returns += 1,
                    Terminator::Jump(next) => {
                        assert_ne!(
                            block.label, *next,
                            "{name} exposes a compiler-only dead continuation"
                        );
                        pending.push(*next);
                    }
                    Terminator::Branch {
                        then_bb, else_bb, ..
                    } => {
                        pending.push(*then_bb);
                        pending.push(*else_bb);
                    }
                }
            }
            assert!(
                reachable_returns >= 2,
                "{name} must preserve both the yielding and explicit-return paths"
            );
        }
    }
    #[test]
    fn lower_pointer_constructors_to_datarefs() {
        let src = include_str!("ir/fixtures/v1/i037.ko");
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        // Expect DataRef instructions for each constructor
        let mut saw_name = false;
        let mut saw_json = false;
        let mut saw_domain = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                if let Instr::DataRef { kind, value, .. } = instr {
                    if *kind == DataRefKind::Name && value == "cursor" {
                        saw_name = true;
                    }
                    if *kind == DataRefKind::Json && value == "{}" {
                        saw_json = true;
                    }
                    if *kind == DataRefKind::Domain && value == "wonderland.universal" {
                        saw_domain = true;
                    }
                }
            }
        }
        assert!(saw_name && saw_json && saw_domain);
    }
    #[test]
    fn lower_bytes_literal_to_dataref() {
        let src = r#"fn main() { let bytes _b = b"ab"; }"#;
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_blob = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                if let Instr::DataRef { kind, value, .. } = instr
                    && *kind == DataRefKind::Blob
                    && value == "0x6162"
                {
                    saw_blob = true;
                }
            }
        }
        assert!(saw_blob, "expected blob dataref for bytes literal");
    }
    #[test]
    fn source_cannot_lower_setvl_builtin() {
        let src = "fn main() { runtime::set_vector_length(8); }";
        let prog = parse(src).unwrap();
        let error = analyze(&prog).expect_err("vector length is compiler-owned");
        assert!(error.message.contains("unknown function or builtin"));
    }
    #[test]
    fn lower_trigger_event_builtin() {
        let src = "fn main() { let ev = context::trigger_event(); let _kind = ev.get_name(Name::parse(\"kind\")); }";
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_trigger_event = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                if let Instr::GetTriggerEvent { .. } = instr {
                    saw_trigger_event = true;
                }
            }
        }
        assert!(
            saw_trigger_event,
            "expected GetTriggerEvent instruction in lowered IR"
        );
    }
    #[derive(Clone, Copy)]
    enum AliasSource {
        Exact(&'static str),
        CanonicalAccount,
    }

    #[derive(Clone, Copy)]
    enum AliasLiteral {
        Ignore,
        String(&'static str),
        DataRef(DataRefKind, &'static str),
        CanonicalAccount,
    }

    fn assert_alias_lowering(
        id: &str,
        source: AliasSource,
        literal: AliasLiteral,
        expected_resolve: Option<bool>,
        expected_static_account: Option<bool>,
    ) {
        let canonical = iroha_data_model::account::AccountId::new(
            "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
                .parse()
                .expect("public key"),
        )
        .to_string();
        let source = match source {
            AliasSource::Exact(source) => source.to_owned(),
            AliasSource::CanonicalAccount => {
                format!(r#"fn main() {{ let _acct = AccountId::parse("{canonical}"); }}"#)
            }
        };
        let program = lower(&analyze(&parse(&source).unwrap()).unwrap()).expect("lower");
        let instructions = program.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let resolves = instructions
            .iter()
            .any(|instruction| matches!(instruction, Instr::ResolveAccountAlias { .. }));
        let static_account = instructions.iter().any(|instruction| {
            matches!(
                instruction,
                Instr::DataRef {
                    kind: DataRefKind::Account,
                    ..
                }
            )
        });
        if let Some(expected) = expected_resolve {
            assert_eq!(
                resolves, expected,
                "{id}: resolve-account-alias instruction"
            );
        }
        if let Some(expected) = expected_static_account {
            assert_eq!(
                static_account, expected,
                "{id}: static account data reference"
            );
        }
        match literal {
            AliasLiteral::Ignore => {}
            AliasLiteral::String(expected) => assert!(
                instructions.iter().any(
                    |instruction| matches!(instruction, Instr::StringConst { value, .. } if value == expected),
                ),
                "{id}: missing string literal {expected:?}",
            ),
            AliasLiteral::DataRef(kind, expected) => assert!(
                instructions.iter().any(
                    |instruction| matches!(instruction, Instr::DataRef { kind: actual_kind, value, .. } if *actual_kind == kind && value == expected),
                ),
                "{id}: missing {kind:?} literal {expected:?}",
            ),
            AliasLiteral::CanonicalAccount => assert!(
                instructions.iter().any(
                    |instruction| matches!(instruction, Instr::DataRef { kind: DataRefKind::Account, value, .. } if value == &canonical),
                ),
                "{id}: missing canonical account literal",
            ),
        }
    }

    macro_rules! alias_lowering_case {
        ($name:ident, $source:expr, $literal:expr, $resolve:expr, $static_account:expr) => {
            #[test]
            fn $name() {
                assert_alias_lowering(
                    stringify!($name),
                    $source,
                    $literal,
                    $resolve,
                    $static_account,
                );
            }
        };
    }

    alias_lowering_case!(
        lower_resolve_account_alias_builtin,
        AliasSource::Exact(
            "fn main() { let _acct = ledger::account::resolve_alias(alias: \"banking@centralbank\"); }",
        ),
        AliasLiteral::Ignore,
        Some(true),
        None
    );
    alias_lowering_case!(
        lower_resolve_account_alias_builtin_uses_string_literal,
        AliasSource::Exact(
            r#"fn main() { let _acct = ledger::account::resolve_alias(alias: "merchant@paynet"); }"#,
        ),
        AliasLiteral::String("merchant@paynet"),
        Some(true),
        Some(false)
    );
    alias_lowering_case!(
        lower_resolve_account_alias_invalid_literal_uses_string_literal,
        AliasSource::Exact(
            r#"fn main() { let _acct = ledger::account::resolve_alias(alias: "merchant@"); }"#,
        ),
        AliasLiteral::String("merchant@"),
        Some(true),
        Some(false)
    );
    alias_lowering_case!(
        lower_resolve_account_alias_domain_qualified_builtin_uses_string_literal,
        AliasSource::Exact(
            r#"fn main() { let _acct = ledger::account::resolve_alias(alias: "merchant@bank.paynet"); }"#,
        ),
        AliasLiteral::String("merchant@bank.paynet"),
        Some(true),
        Some(false)
    );
    alias_lowering_case!(
        lower_resolve_account_alias_invalid_domain_qualified_literal_uses_string_literal,
        AliasSource::Exact(
            r#"fn main() { let _acct = ledger::account::resolve_alias(alias: "merchant@bank."); }"#,
        ),
        AliasLiteral::String("merchant@bank."),
        Some(true),
        Some(false)
    );
    alias_lowering_case!(
        lower_account_id_alias_literal_to_resolve_account_alias,
        AliasSource::Exact(r#"fn main() { let _acct = AccountId::parse("merchant@paynet"); }"#),
        AliasLiteral::DataRef(DataRefKind::Blob, "merchant@paynet"),
        Some(true),
        Some(false)
    );
    alias_lowering_case!(
        lower_account_id_domain_qualified_alias_literal_to_resolve_account_alias,
        AliasSource::Exact(
            r#"fn main() { let _acct = AccountId::parse("merchant@bank.paynet"); }"#,
        ),
        AliasLiteral::DataRef(DataRefKind::Blob, "merchant@bank.paynet"),
        Some(true),
        Some(false)
    );
    #[test]
    fn account_id_invalid_non_alias_literal_is_rejected_before_lowering() {
        // A literal that is neither canonical I105 nor alias-shaped never
        // reaches lowering: semantic analysis rejects it with its span.
        let program = parse(r#"fn main() { let _acct = AccountId::parse("merchant"); }"#)
            .expect("parse invalid account literal");
        let error = analyze(&program).expect_err("non-alias invalid AccountId literal");
        assert_eq!(error.code, "E_INVALID_ID_LITERAL");
    }
    alias_lowering_case!(
        lower_account_id_canonical_literal_to_static_account_dataref,
        AliasSource::CanonicalAccount,
        AliasLiteral::CanonicalAccount,
        Some(false),
        Some(true)
    );
    alias_lowering_case!(
        lower_account_id_invalid_alias_shaped_literal_to_resolve_account_alias,
        AliasSource::Exact(r#"fn main() { let _acct = AccountId::parse("merchant@"); }"#),
        AliasLiteral::Ignore,
        Some(true),
        Some(false)
    );
    alias_lowering_case!(
        lower_account_id_invalid_domain_qualified_alias_literal_to_resolve_account_alias,
        AliasSource::Exact(r#"fn main() { let _acct = AccountId::parse("merchant@bank."); }"#),
        AliasLiteral::Ignore,
        Some(true),
        Some(false)
    );
    #[test]
    fn lower_get_quantity_builtin() {
        let src = "fn main() { let ev = context::trigger_event(); let Option<quantity> value = ev.get_quantity(Name::parse(\"value\")); }";
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_get_numeric = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                if let Instr::JsonGetNumeric {
                    kind: WideNumericKind::Quantity,
                    ..
                } = instr
                {
                    saw_get_numeric = true;
                }
            }
        }
        assert!(
            saw_get_numeric,
            "expected quantity JsonGetNumeric instruction in lowered IR"
        );
    }
    #[test]
    fn lower_quantity_typed_integer_literal_to_quantity_dataref() {
        let src = include_str!("ir/fixtures/v1/i038.ko");
        let program = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let amount = program
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .find_map(|instruction| match instruction {
                Instr::MintAsset { amount, .. } => Some(*amount),
                _ => None,
            })
            .expect("mint amount temp");
        assert!(
            program
                .functions
                .iter()
                .flat_map(|function| &function.blocks)
                .flat_map(|block| &block.instrs)
                .any(|instruction| matches!(
                    instruction,
                    Instr::DataRef {
                        dest,
                        kind: DataRefKind::Quantity,
                        value,
                    } if *dest == amount && value == "1"
                ))
        );
    }
    #[test]
    fn lower_get_asset_definition_id_builtin() {
        let src = "fn main() { let ev = context::trigger_event(); let _asset = ev.get_asset_definition_id(Name::parse(\"asset_definition_id\")); }";
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_get_asset_definition_id = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                if let Instr::JsonGetAssetDefinitionId { .. } = instr {
                    saw_get_asset_definition_id = true;
                }
            }
        }
        assert!(
            saw_get_asset_definition_id,
            "expected JsonGetAssetDefinitionId instruction in lowered IR"
        );
    }
    #[test]
    fn lower_state_map_sets_keep_declared_base_names() {
        let src = include_str!("ir/fixtures/v1/i039.ko");
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let update_record = ir
            .functions
            .iter()
            .find(|func| func.name == "update_record")
            .expect("update_record function");
        let mut name_literals = HashMap::new();
        let mut bases = Vec::new();
        for block in &update_record.blocks {
            for instr in &block.instrs {
                if let Instr::DataRef {
                    dest,
                    kind: DataRefKind::Name,
                    value,
                } = instr
                {
                    name_literals.insert(*dest, value.clone());
                }
                if let Instr::PathMapKeyNorito { base, .. } = instr {
                    let base_name = name_literals
                        .get(base)
                        .cloned()
                        .expect("PathMapKey base should originate from a Name DataRef");
                    bases.push(base_name);
                }
            }
        }
        assert_eq!(
            bases,
            vec![
                "MintRequestSequences",
                "MintRequestRequestIds",
                "MintRequestFiIds",
                "MintRequestFiAuthorities",
                "MintRequestToAccounts",
                "MintRequestAmounts",
                "MintRequestRequestedBy",
                "MintRequestStates",
                "MintRequestCreatedAt",
                "MintRequestExpiresAt",
                "MintRequestFinalizedAt",
                "MintRequestCanceledAt",
            ]
        );
    }
    #[test]
    fn lower_bytes_literal_to_blob_dataref() {
        let src = r#"fn main() { let _b = b"ab"; }"#;
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_blob = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                if let Instr::DataRef { kind, value, .. } = instr
                    && *kind == DataRefKind::Blob
                    && value == "0x6162"
                {
                    saw_blob = true;
                }
            }
        }
        assert!(saw_blob, "expected Blob dataref for bytes literal");
    }
    #[test]
    fn lower_canonical_trigger_operations() {
        let src = include_str!("ir/fixtures/v1/i040.ko");
        let ir = lower(&analyze(&parse(src).unwrap()).unwrap()).expect("lower");
        let f = &ir.functions[0];
        let mut saw_create = false;
        let mut saw_remove = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::CreateTrigger { .. } => saw_create = true,
                    Instr::RemoveTrigger { .. } => saw_remove = true,
                    _ => {}
                }
            }
        }
        assert!(saw_create && saw_remove);
    }
    #[test]
    fn lower_struct_fields_for_transfer_domain() {
        let src = include_str!("ir/fixtures/v1/i041.ko");
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = ir.functions.iter().find(|f| f.name == "main").unwrap();
        let mut saw_transfer = false;
        for bb in &f.blocks {
            for ins in &bb.instrs {
                if let Instr::TransferDomain { .. } = ins {
                    saw_transfer = true;
                }
            }
        }
        assert!(saw_transfer, "expected TransferDomain in lowered IR");
    }
    #[test]
    fn lower_info_int_preserves_full_width_pointer() {
        let src = "fn f() { debug::info(7); }";
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_encode = false;
        let mut saw_info = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::PointerToNorito { .. } => saw_encode = true,
                    Instr::Info { .. } => saw_info = true,
                    _ => {}
                }
            }
        }
        assert!(
            saw_encode,
            "expected full-width pointer encoding before Info"
        );
        assert!(saw_info, "expected Info instruction");
    }
    #[test]
    fn source_cannot_lower_internal_encode_i64_builtin() {
        let src = "fn f() { let _b = codec::encode_i64(7); }";
        let prog = parse(src).unwrap();
        let error = analyze(&prog).expect_err("codec builtin is compiler-owned");
        assert!(
            error.message.contains("compiler-internal")
                || error.message.contains("unknown function or builtin"),
            "unexpected error: {}",
            error.message
        );
    }
    #[test]
    fn lower_bytes_equality_uses_pointer_eq() {
        let src = r#"fn f() { let a = b"hi"; let b = b"hi"; let _x = a == b; }"#;
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut saw_pointer_eq = false;
        let mut saw_binary_eq = false;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::PointerEq { .. } => saw_pointer_eq = true,
                    Instr::Binary {
                        op: BinaryOp::Eq, ..
                    } => saw_binary_eq = true,
                    _ => {}
                }
            }
        }
        assert!(saw_pointer_eq, "expected PointerEq for blob comparison");
        assert!(
            !saw_binary_eq,
            "blob equality should not lower to integer compare"
        );
    }
    #[test]
    fn lower_get_unwrap_or_on_state_map_reads_without_writing() {
        let src = "state StateMap<int, int> balances; fn f() -> int { return balances.get(1).unwrap_or(7); }";
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let mut state_gets = 0;
        let mut state_sets = 0;
        for bb in &f.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::StateGet { .. } => state_gets += 1,
                    Instr::StateSet { .. } => state_sets += 1,
                    _ => {}
                }
            }
        }
        assert!(
            state_gets >= 1,
            "expected get(...).unwrap_or durable path to read state"
        );
        assert_eq!(
            state_sets, 0,
            "get(...).unwrap_or must not mutate durable state"
        );
    }
    #[test]
    fn lower_get_or_insert_writes_the_default_only_on_absence() {
        let src = "permission W; state StateMap<int, int> balances; kotoage fn f() authorize(W) -> int { return balances.get_or_insert(1, 7); }";
        let typed = analyze(&parse(src).unwrap()).unwrap();
        let ir = lower(&typed).expect("lower");
        let f = &ir.functions[0];
        let (mut state_gets, mut state_sets) = (0, 0);
        for instr in f.blocks.iter().flat_map(|bb| &bb.instrs) {
            match instr {
                Instr::StateGet { .. } => state_gets += 1,
                Instr::StateSet { .. } => state_sets += 1,
                _ => {}
            }
        }
        assert!(state_gets >= 1, "get_or_insert reads before writing");
        assert!(state_sets >= 1, "get_or_insert writes the default");
    }
    #[test]
    fn transfer_without_dataspace_passes_a_null_scope_word() {
        let src = "fn pay(AccountId from, AccountId to, AssetDefinitionId asset) { ledger::asset::transfer(source: from, destination: to, asset_definition: asset, amount: 1); }";
        let typed = analyze(&parse(src).unwrap()).unwrap();
        let ir = lower(&typed).expect("lower");
        let instrs = ir.functions[0]
            .blocks
            .iter()
            .flat_map(|bb| &bb.instrs)
            .collect::<Vec<_>>();
        let dataspace = instrs
            .iter()
            .find_map(|instr| match instr {
                Instr::TransferAsset { dataspace, .. } => Some(*dataspace),
                _ => None,
            })
            .expect("transfer lowers to TransferAsset");
        assert!(
            instrs.iter().any(|instr| matches!(
                instr,
                Instr::Const { dest, value: 0 } if *dest == dataspace
            )),
            "an omitted dataspace must lower to the zero scope word"
        );
    }
    #[test]
    fn signature_scheme_values_pass_their_host_scheme_code() {
        for (path, code) in [
            ("SignatureScheme::Ed25519", 1),
            ("SignatureScheme::Secp256k1", 2),
            ("SignatureScheme::MlDsa", 3),
        ] {
            let src = format!(
                "fn check(bytes payload) -> bool {{ return crypto::verify_signature(message: payload, signature: payload, public_key: payload, scheme: {path}); }}"
            );
            let typed = analyze(&parse(&src).unwrap()).unwrap();
            let ir = lower(&typed).expect("lower");
            let instrs = ir.functions[0]
                .blocks
                .iter()
                .flat_map(|bb| &bb.instrs)
                .collect::<Vec<_>>();
            let scheme = instrs
                .iter()
                .find_map(|instr| match instr {
                    Instr::VerifySignature { scheme, .. } => Some(*scheme),
                    _ => None,
                })
                .expect("verification lowers to VerifySignature");
            assert!(
                instrs.iter().any(|instr| matches!(
                    instr,
                    Instr::Const { dest, value } if *dest == scheme && *value == code
                )),
                "{path} must pass scheme code {code}"
            );
        }
    }
    #[test]
    fn scalar_state_map_get_reuses_presence_blob() {
        let src = "state StateMap<int, int> balances; fn f() { let _value = balances.get(1); }";
        let typed = analyze(&parse(src).expect("parse StateMap.get")).expect("analyze");
        let ir = lower(&typed).expect("lower");
        let state_gets = ir.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| matches!(instruction, Instr::StateGet { .. }))
            .count();
        assert_eq!(state_gets, 1, "presence and scalar value share one read");
    }
    #[test]
    fn scalar_state_map_remove_reads_and_deletes_once() {
        let src = "state StateMap<int, int> balances; fn f() { let _value = balances.remove(1); }";
        let typed = analyze(&parse(src).expect("parse StateMap.remove")).expect("analyze");
        let ir = lower(&typed).expect("lower");
        let instructions = ir.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| matches!(instruction, Instr::StateGet { .. }))
                .count(),
            1
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| matches!(instruction, Instr::StateDel { .. }))
                .count(),
            1
        );
    }
    #[test]
    fn lower_state_struct_ident_decodes_one_schema_bound_record() {
        let src = include_str!("ir/fixtures/v1/i042.ko");
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let main_fn = ir.functions.iter().find(|f| f.name == "main").unwrap();
        let mut saw_tuple_pack = false;
        let mut root_paths = Vec::new();
        let mut saw_legacy_name_root = false;
        let mut saw_aggregate_decode = false;
        let mut state_get_paths = Vec::new();
        for bb in &main_fn.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::TuplePack { .. } => saw_tuple_pack = true,
                    Instr::DataRef {
                        dest,
                        kind: DataRefKind::NoritoBytes,
                        value,
                        ..
                    } => {
                        if let Some(encoded) = value
                            .strip_prefix("0x")
                            .and_then(|raw| hex::decode(raw).ok())
                            && let Ok(path) =
                                ivm_abi::codec::decode_canonical_norito::<StatePath>(&encoded)
                            && path.as_ref() == "ledger"
                        {
                            root_paths.push(*dest);
                        }
                    }
                    Instr::DataRef {
                        kind: DataRefKind::Name,
                        value,
                        ..
                    } if value == "ledger" => saw_legacy_name_root = true,
                    Instr::DirectHelperSyscall { syscall, .. }
                        if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE =>
                    {
                        saw_aggregate_decode = true;
                    }
                    Instr::StateGet { path, .. } => state_get_paths.push(*path),
                    _ => {}
                }
            }
        }
        assert!(
            saw_tuple_pack,
            "expected TuplePack when reconstructing struct state"
        );
        assert!(
            !saw_legacy_name_root,
            "durable ledger root must not use the retired Name transport"
        );
        assert_eq!(
            root_paths.len(),
            1,
            "durable ledger root must have one canonical NoritoBytes(StatePath) literal"
        );
        assert_eq!(
            state_get_paths, root_paths,
            "the one durable read must consume the canonical ledger StatePath"
        );
        assert!(saw_aggregate_decode, "missing aggregate state decoder");
        assert_eq!(
            state_get_paths.len(),
            1,
            "aggregate state must be read exactly once"
        );
    }
    #[test]
    fn named_struct_literal_lowers_in_declaration_order() {
        let program = parse(include_str!(
            "ir/test_sources/named_struct_literal_lowers_in_declaration_order_1.ko"
        ))
        .expect("parse named struct literal");
        let typed = analyze(&program).expect("analyze named struct literal");
        let lowered = lower(&typed).expect("lower named struct literal");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let constants = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| match instruction {
                Instr::DataRef {
                    dest,
                    kind: DataRefKind::Int,
                    value,
                } => Some((*dest, value.as_str())),
                _ => None,
            })
            .collect::<HashMap<_, _>>();
        let items = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .find_map(|instruction| match instruction {
                Instr::TuplePack { items, .. } if items.len() == 2 => Some(items),
                _ => None,
            })
            .expect("struct TuplePack");
        assert_eq!(constants.get(&items[0]), Some(&"1"));
        assert_eq!(constants.get(&items[1]), Some(&"2"));
    }
    #[test]
    fn named_struct_literal_evaluates_fields_in_source_order_before_layout() {
        let program = parse(
            include_str!("ir/test_sources/named_struct_literal_evaluates_fields_in_source_order_before_layout_1.ko"),
        )
        .expect("parse effectful named struct literal");
        let lowered = lower(&analyze(&program).expect("analyze named struct effects"))
            .expect("lower named struct effects");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let calls = main
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .filter_map(|instruction| match instruction {
                Instr::Call { callee, dest, .. } => Some((callee.as_str(), *dest)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            calls.iter().map(|(callee, _)| *callee).collect::<Vec<_>>(),
            ["second", "first"]
        );
        let packed = main
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .find_map(|instruction| match instruction {
                Instr::TuplePack { items, .. } if items.len() == 2 => Some(items),
                _ => None,
            })
            .expect("struct TuplePack");
        assert_eq!(packed, &[calls[1].1.unwrap(), calls[0].1.unwrap()]);
    }
    #[test]
    fn lower_state_struct_assignment_encodes_and_writes_once() {
        let src = include_str!("ir/fixtures/v1/i043.ko");
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let main_fn = ir.functions.iter().find(|f| f.name == "main").unwrap();
        let mut root_paths = Vec::new();
        let mut saw_legacy_name_root = false;
        let mut state_set_paths = Vec::new();
        let mut tuple_gets = 0;
        let mut aggregate_encodes = 0;
        for bb in &main_fn.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::DataRef {
                        dest,
                        kind: DataRefKind::NoritoBytes,
                        value,
                        ..
                    } => {
                        if let Some(encoded) = value
                            .strip_prefix("0x")
                            .and_then(|raw| hex::decode(raw).ok())
                            && let Ok(path) =
                                ivm_abi::codec::decode_canonical_norito::<StatePath>(&encoded)
                            && path.as_ref() == "ledger"
                        {
                            root_paths.push(*dest);
                        }
                    }
                    Instr::DataRef {
                        kind: DataRefKind::Name,
                        value,
                        ..
                    } if value == "ledger" => saw_legacy_name_root = true,
                    Instr::StateSet { path, .. } => state_set_paths.push(*path),
                    Instr::TupleGet { .. } => tuple_gets += 1,
                    Instr::StateValueEncode { .. } => aggregate_encodes += 1,
                    _ => {}
                }
            }
        }
        assert_eq!(
            root_paths.len(),
            1,
            "durable ledger root must have one canonical NoritoBytes(StatePath) literal"
        );
        assert!(
            !saw_legacy_name_root,
            "durable ledger root must not use the retired Name transport"
        );
        assert_eq!(
            state_set_paths, root_paths,
            "the one durable write must consume the canonical ledger StatePath"
        );
        assert_eq!(
            state_set_paths.len(),
            1,
            "aggregate state must be written exactly once"
        );
        assert_eq!(aggregate_encodes, 1, "aggregate state must be encoded once");
        assert!(
            tuple_gets >= 2,
            "expected tuple extraction for the canonical aggregate record"
        );
    }
    #[test]
    fn aggregate_state_map_entry_uses_one_read_and_one_write() {
        let src = include_str!("ir/fixtures/v1/i044.ko");
        let prog = parse(src).unwrap();
        let typed = analyze(&prog).unwrap();
        let ir = lower(&typed).expect("lower");
        let main_fn = ir.functions.iter().find(|f| f.name == "main").unwrap();
        let mut state_gets = 0;
        let mut state_sets = 0;
        let mut aggregate_encodes = 0;
        let mut aggregate_decodes = 0;
        let mut child_paths = Vec::new();
        for bb in &main_fn.blocks {
            for instr in &bb.instrs {
                match instr {
                    Instr::DataRef {
                        kind: DataRefKind::Name,
                        value,
                        ..
                    } if value.contains('#') || value.contains("ledgers_") => {
                        child_paths.push(value.clone());
                    }
                    Instr::StateGet { .. } => state_gets += 1,
                    Instr::StateSet { .. } => state_sets += 1,
                    Instr::StateValueEncode { .. } => aggregate_encodes += 1,
                    Instr::DirectHelperSyscall { syscall, .. }
                        if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE =>
                    {
                        aggregate_decodes += 1;
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(state_sets, 1, "StateMap aggregate must use one host write");
        assert_eq!(state_gets, 1, "StateMap aggregate must use one host read");
        assert_eq!(
            aggregate_encodes, 3,
            "encode the write key, value and read key once each"
        );
        assert_eq!(aggregate_decodes, 1);
        assert!(
            child_paths.is_empty(),
            "unexpected child paths: {child_paths:?}"
        );
    }
    #[test]
    fn sum_error_bridges_lower_fallbacks_only_in_the_failure_block() {
        let source = r#"module Bridges {
            error enum Previous { Denied = 1 }
            error enum Failure { Missing = 7 }
            fn fallback() -> Failure { Failure::Missing }
            fn receiver(bool present) -> Option<(int, bool)> {
                if present { Option::some((7, true)) } else { Option::none }
            }
            fn convert(bool present) -> Result<(int, bool), Failure> {
                receiver(present).ok_or(error: fallback())
            }
            fn replace(Result<int, Previous> value) -> Result<int, Failure> {
                value.or_err(error: fallback())
            }
            fn extract(Result<int, Previous> value) -> int { value.expect(error: fallback()) }
        }"#;
        let typed = analyze(&parse(source).expect("parse lazy error bridges"))
            .expect("type lazy error bridges");
        let lowered = lower(&typed).expect("lower lazy error bridges");
        for name in ["convert", "replace", "extract"] {
            let function = lowered
                .functions
                .iter()
                .find(|function| function.name == name)
                .unwrap();
            let branch = function
                .blocks
                .iter()
                .find_map(|block| match block.terminator {
                    Terminator::Branch { else_bb, .. } => Some((block, else_bb)),
                    _ => None,
                })
                .expect("sum tag selects a success or failure branch");
            let fallback_blocks = function.blocks.iter().filter(|block| block.instrs.iter().any(|instruction| {
                matches!(instruction, Instr::Call { callee, .. } | Instr::CallMulti { callee, .. } if callee == "fallback")
            })).map(|block| block.label).collect::<Vec<_>>();
            assert_eq!(
                fallback_blocks,
                vec![branch.1],
                "{name}: fallback belongs only to the failing branch"
            );
            if name == "convert" {
                assert_eq!(branch.0.instrs.iter().filter(|instruction| {
                    matches!(instruction, Instr::Call { callee, .. } | Instr::CallMulti { callee, .. } if callee == "receiver")
                }).count(), 1, "receiver is captured once before branching");
            }
        }
    }
    #[test]
    fn aggregate_unwrap_or_lowers_one_eager_fallback_call() {
        let source = include_str!("ir/fixtures/v1/i045.ko");
        let program = parse(source).expect("parse mixed aggregate unwrap_or");
        let typed = analyze(&program).expect("analyze mixed aggregate unwrap_or");
        let lowered = lower(&typed).expect("lower mixed aggregate unwrap_or");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let fallback_calls = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| {
                matches!(
                    instruction,
                    Instr::CallMulti { callee, .. } if callee == "observed_fallback"
                )
            })
            .count();
        assert_eq!(
            fallback_calls, 1,
            "eager unwrap_or must evaluate an effectful fallback exactly once"
        );
    }
    #[test]
    fn tuple_binding_projects_one_captured_call_result() {
        let source = include_str!("ir/fixtures/v1/i046.ko");
        let program = parse(source).expect("parse tuple call binding");
        let typed = analyze(&program).expect("analyze tuple call binding");
        let lowered = lower(&typed).expect("lower tuple call binding");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let calls = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| {
                matches!(
                    instruction,
                    Instr::CallMulti { callee, .. } if callee == "observed_pair"
                )
            })
            .count();
        assert_eq!(
            calls, 1,
            "tuple field bindings must project one captured call result"
        );
    }
    #[test]
    fn tuple_destructuring_projects_one_captured_call_result() {
        let source = include_str!("ir/fixtures/v1/i047.ko");
        let program = parse(source).expect("parse tuple destructuring call");
        let typed = analyze(&program).expect("analyze tuple destructuring call");
        let lowered = lower(&typed).expect("lower tuple destructuring call");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let calls = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| {
                matches!(
                    instruction,
                    Instr::CallMulti { callee, .. } if callee == "observed_pair"
                )
            })
            .count();
        assert_eq!(
            calls, 1,
            "tuple destructuring must project one captured call result"
        );
    }
    #[test]
    fn nested_struct_binding_projects_one_captured_call_result() {
        let source = include_str!("ir/fixtures/v1/i048.ko");
        let program = parse(source).expect("parse nested struct call binding");
        let typed = analyze(&program).expect("analyze nested struct call binding");
        let lowered = lower(&typed).expect("lower nested struct call binding");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let calls = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| {
                matches!(
                    instruction,
                    Instr::CallMulti { callee, .. } if callee == "observed_outer"
                )
            })
            .count();
        assert_eq!(
            calls, 1,
            "nested struct fields must project one captured call result"
        );
    }
    #[test]
    fn scalar_state_read_after_write_reuses_the_live_value() {
        let src = include_str!("ir/fixtures/v1/i049.ko");
        let prog = parse(src).expect("parse scalar state root");
        let typed = analyze(&prog).expect("analyze scalar state root");
        let ir = lower(&typed).expect("lower scalar state root");
        let main_fn = ir.functions.iter().find(|f| f.name == "main").unwrap();
        let encodes = main_fn
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instr| matches!(instr, Instr::StateValueEncode { .. }))
            .count();
        let decodes = main_fn
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instr| {
                matches!(
                    instr,
                    Instr::DirectHelperSyscall { syscall, .. }
                        if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE
                )
            })
            .count();
        assert_eq!(encodes, 1, "scalar root must be encoded exactly once");
        assert_eq!(
            decodes, 0,
            "a scalar read immediately after its write must reuse the live value"
        );
    }
    #[test]
    fn durable_state_cache_reloads_after_guest_calls() {
        let source = "state int trace; hajimari() { trace = 0; } fn mutate() { trace = 7; } fn main() -> int { trace = 0; let before = trace; mutate(); let after = trace; before + after }";
        let lowered = lower(
            &analyze(&parse(source).expect("parse state cache regression"))
                .expect("analyze state cache regression"),
        )
        .expect("lower state cache regression");
        let main = lowered
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let instructions = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let call = instructions.iter().position(|instruction| matches!(instruction, Instr::Call { callee, .. } if callee == "mutate")).expect("effectful guest call");
        assert!(
            !instructions[..call]
                .iter()
                .any(|instruction| matches!(instruction, Instr::StateGet { .. })),
            "immediate read-after-write retains the local block cache"
        );
        assert!(
            instructions[call + 1..]
                .iter()
                .any(|instruction| matches!(instruction, Instr::StateGet { .. })),
            "a callee may change durable state before the next source read"
        );
    }
    #[test]
    fn missing_aggregate_map_entry_branches_before_typed_decode() {
        let src = include_str!("ir/fixtures/v1/i050.ko");
        let prog = parse(src).expect("parse aggregate map read");
        let typed = analyze(&prog).expect("analyze aggregate map read");
        let ir = lower(&typed).expect("lower aggregate map read");
        let main_fn = ir.functions.iter().find(|f| f.name == "main").unwrap();
        let decode_block = main_fn
            .blocks
            .iter()
            .find(|block| {
                block.instrs.iter().any(|instr| {
                    matches!(
                        instr,
                        Instr::DirectHelperSyscall { syscall, .. }
                            if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE
                    )
                })
            })
            .expect("present branch must decode the typed record");
        let presence_branch = main_fn
            .blocks
            .iter()
            .find_map(|block| match &block.terminator {
                Terminator::Branch {
                    then_bb, else_bb, ..
                } if *then_bb == decode_block.label => Some((*then_bb, *else_bb)),
                _ => None,
            })
            .expect("typed decode must be guarded by presence");
        assert_ne!(presence_branch.0, presence_branch.1);
        let absent = main_fn
            .blocks
            .iter()
            .find(|block| block.label == presence_branch.1)
            .expect("absent branch");
        assert!(
            absent.instrs.iter().all(|instr| !matches!(
                instr,
                Instr::DirectHelperSyscall { syscall, .. }
                    if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE
            )),
            "missing entries must never be passed to the typed decoder"
        );
    }
    #[test]
    fn bytes_state_map_uses_the_schema_bound_record_codec() {
        let source = include_str!("ir/fixtures/v1/i051.ko");
        let program = parse(source).expect("parse bytes state map");
        let typed = analyze(&program).expect("analyze bytes state map");
        let ir = lower(&typed).expect("lower bytes state map");
        let main = ir
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main function");
        let encodes = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| matches!(instruction, Instr::StateValueEncode { .. }))
            .count();
        let decodes = main
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| {
                matches!(
                    instruction,
                    Instr::DirectHelperSyscall { syscall, .. }
                        if *syscall == ivm_abi::syscalls::SYSCALL_STATE_VALUE_DECODE
                )
            })
            .count();
        assert_eq!(
            encodes, 3,
            "both map keys and the written value use the same typed codec"
        );
        assert_eq!(decodes, 1, "bytes map reads must use the typed codec");
    }
    #[test]
    fn checked_integer_constants_fold_without_wrapping() {
        const MAXIMUM: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047";
        let safe = parse(&format!(
            "fn main() -> int {{ return ({MAXIMUM} - 1) + 1; }}"
        ))
        .expect("parse safe constant expression");
        let safe = lower(&analyze(&safe).expect("analyze safe constant expression"))
            .expect("lower safe constant expression");
        assert!(safe.functions[0].blocks.iter().any(|block| {
            block.instrs.iter().any(|instr| {
                matches!(
                    instr,
                    Instr::DataRef {
                        kind: DataRefKind::Int,
                        value,
                        ..
                    } if value == MAXIMUM
                )
            })
        }));
        let overflow = parse(&format!("fn main() -> int {{ return {MAXIMUM} + 1; }}"))
            .expect("parse overflowing constant expression");
        let error = analyze(&overflow).expect_err("constant overflow must not wrap");
        assert!(error.code == "E_INT_OVERFLOW", "unexpected error: {error}");
    }
    #[test]
    fn exact_decimal_constants_fold_and_invalid_arithmetic_is_diagnosed() {
        let safe = parse("fn main() -> decimal { return 1.0 / 8.0; }")
            .expect("parse exact decimal constant");
        let safe = lower(&analyze(&safe).expect("analyze exact decimal constant"))
            .expect("lower exact decimal constant");
        assert!(safe.functions[0].blocks.iter().any(|block| {
            block.instrs.iter().any(|instruction| {
                matches!(
                    instruction,
                    Instr::DataRef {
                        kind: DataRefKind::Decimal,
                        value,
                        ..
                    } if value == "0.125"
                )
            })
        }));
        for (source, code) in [
            (
                "fn main() -> quantity { return 1 - 2; }",
                "E_QUANTITY_UNDERFLOW",
            ),
            (
                "fn main() -> decimal { return 1.0 / 3.0; }",
                "E_REPEATING_DECIMAL",
            ),
        ] {
            let program = parse(source).expect("parse invalid constant numeric arithmetic");
            let error = analyze(&program)
                .expect_err("invalid constant numeric arithmetic must fail semantic checking");
            assert_eq!(error.code, code);
        }
    }
    #[test]
    fn native_event_lowering_captures_each_field_once_before_emission() {
        let typed = analyze(
            &parse(
                r#"seiyaku Events {
            event Pair { int first; int second; }
            fn first() -> int { 1 }
            fn second() -> int { 2 }
            kotoage fn run() authorize(anyone) { emit Pair { second: second(), first: first() }; }
        }"#,
            )
            .unwrap(),
        )
        .unwrap();
        let lowered = lower(&typed).unwrap();
        let instructions = lowered
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .collect::<Vec<_>>();
        let calls = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::Call { callee, .. } if callee == "first" || callee == "second" => {
                    Some(callee.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(calls, ["second", "first"]);
        let emissions = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instr::DirectHelperSyscall { syscall, args, .. }
                    if *syscall == ivm_abi::syscalls::SYSCALL_EMIT_CONTRACT_EVENT =>
                {
                    Some(args)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(emissions.len(), 1);
        assert_eq!(emissions[0].len(), 3);
        assert!(!instructions.iter().any(|instruction| matches!(instruction, Instr::DirectHelperSyscall { syscall, .. } if *syscall == ivm_abi::syscalls::SYSCALL_JSON_BUILD)));
    }
    include!("ir_tail_tests.rs");
}
