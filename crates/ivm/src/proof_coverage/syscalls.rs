//! Every ABI V1 syscall mapped to its whole-invocation relation obligations.
//!
//! Numbers come from `abi_syscall_list()` and names from
//! `ABI_V1_SYSCALL_METADATA` through `syscall_name`; tests compare this table
//! against both in each direction, so an added, removed or renamed syscall
//! fails until it is inventoried. No syscall has a proof relation today: each
//! result, trap and statement binding is tracked separately and starts
//! uncovered.

use super::{CoverageStatus, Obligation};
use crate::syscalls::{self, SyscallAccess};

/// Relation class shared by syscalls with the same proof obligations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallRelation {
    /// Terminates the invocation successfully or with an application abort.
    Terminal,
    /// Host-visible diagnostic output without a ledger effect.
    Diagnostic,
    /// Queues one canonical ledger instruction or administrative effect.
    LedgerEffect,
    /// Emits a typed event bound to the authenticated invocation and signed schema.
    ContractEvent,
    /// Reads contract-owned durable state.
    ContractStateRead,
    /// Writes contract-owned durable state.
    ContractStateWrite,
    /// Reads ledger state through a typed or generic query.
    LedgerQuery,
    /// Resolves the epoch seed from finalized beacon pulses.
    VrfEpochSeed,
    /// SoraCloud service request whose semantic depends on the attached host.
    SoraCloud,
    /// Reads a value bound to the invocation's public context.
    ExecutionContext,
    /// Deterministic typed codec work over public pointer-ABI values.
    TypedCodec,
    /// Exact Kotodama V1 numeric operation with staged metering.
    Numeric,
    /// Hash precompile over a public blob.
    HashPrecompile,
    /// Signature or VRF verification precompile.
    SignaturePrecompile,
    /// Authenticated-cipher precompile.
    CipherPrecompile,
    /// Verifies a proof on behalf of the guest.
    GuestProofVerification,
    /// AXT envelope lifecycle, including its dataspace proof check.
    Axt,
    /// Guest heap allocation or growth.
    HeapMemory,
    /// Reads the VM's own memory, register or execution commitments.
    TraceCommitment,
    /// Private witness access and value commitment.
    PrivateWitness,
    /// Commits the public output of the invocation.
    PublicOutput,
    /// Invokes another contract entrypoint inside the same transaction.
    NestedInvocation,
    /// Routes a dynamically selected instruction or execution policy change.
    DynamicInstruction,
}

use Obligation::{
    Calls, Continuation, Copyback, Faults, Gas, GuestProofVerification, HostResult, Initialization,
    MemoryOrdering, Padding, Pointers, Precompile, PrivateMasking, ProofComposition, StateEffect,
    StateRead, StatementBinding, TypedValues, VmRecursion,
};

impl SyscallRelation {
    /// Number of relation classes.
    pub const COUNT: usize = 23;

    /// Every relation class in stable order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Terminal,
        Self::Diagnostic,
        Self::LedgerEffect,
        Self::ContractEvent,
        Self::ContractStateRead,
        Self::ContractStateWrite,
        Self::LedgerQuery,
        Self::VrfEpochSeed,
        Self::SoraCloud,
        Self::ExecutionContext,
        Self::TypedCodec,
        Self::Numeric,
        Self::HashPrecompile,
        Self::SignaturePrecompile,
        Self::CipherPrecompile,
        Self::GuestProofVerification,
        Self::Axt,
        Self::HeapMemory,
        Self::TraceCommitment,
        Self::PrivateWitness,
        Self::PublicOutput,
        Self::NestedInvocation,
        Self::DynamicInstruction,
    ];

    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Diagnostic => "diagnostic",
            Self::LedgerEffect => "ledger_effect",
            Self::ContractEvent => "contract_event",
            Self::ContractStateRead => "contract_state_read",
            Self::ContractStateWrite => "contract_state_write",
            Self::LedgerQuery => "ledger_query",
            Self::VrfEpochSeed => "vrf_epoch_seed",
            Self::SoraCloud => "soracloud",
            Self::ExecutionContext => "execution_context",
            Self::TypedCodec => "typed_codec",
            Self::Numeric => "numeric",
            Self::HashPrecompile => "hash_precompile",
            Self::SignaturePrecompile => "signature_precompile",
            Self::CipherPrecompile => "cipher_precompile",
            Self::GuestProofVerification => "guest_proof_verification",
            Self::Axt => "axt",
            Self::HeapMemory => "heap_memory",
            Self::TraceCommitment => "trace_commitment",
            Self::PrivateWitness => "private_witness",
            Self::PublicOutput => "public_output",
            Self::NestedInvocation => "nested_invocation",
            Self::DynamicInstruction => "dynamic_instruction",
        }
    }

    /// Relation obligation classes every syscall of this class engages, in
    /// addition to those of the dispatching `SCALL`/`SYSTEM` opcode.
    #[must_use]
    pub const fn obligations(self) -> &'static [Obligation] {
        match self {
            Self::Terminal => &[Faults, Gas, Padding, HostResult, StatementBinding],
            Self::Diagnostic => &[Pointers, Gas, Faults, HostResult],
            Self::LedgerEffect | Self::DynamicInstruction => &[
                Pointers,
                Gas,
                Faults,
                HostResult,
                StateEffect,
                StatementBinding,
            ],
            Self::ContractEvent => &[
                TypedValues,
                Initialization,
                MemoryOrdering,
                Pointers,
                Gas,
                Faults,
                HostResult,
                StateRead,
                StateEffect,
                StatementBinding,
            ],
            Self::ContractStateRead | Self::LedgerQuery => {
                &[MemoryOrdering, Pointers, Gas, Faults, HostResult, StateRead]
            }
            Self::ContractStateWrite => {
                &[Pointers, Gas, Faults, HostResult, StateRead, StateEffect]
            }
            Self::VrfEpochSeed => &[
                MemoryOrdering,
                Pointers,
                Gas,
                Faults,
                HostResult,
                StateRead,
                StatementBinding,
            ],
            Self::SoraCloud => &[
                MemoryOrdering,
                Pointers,
                Gas,
                Faults,
                HostResult,
                StateRead,
                StateEffect,
            ],
            Self::ExecutionContext => &[Pointers, Gas, Faults, HostResult, StatementBinding],
            Self::TypedCodec => &[
                TypedValues,
                Initialization,
                MemoryOrdering,
                Pointers,
                Gas,
                Faults,
                HostResult,
            ],
            Self::Numeric => &[
                TypedValues,
                MemoryOrdering,
                Pointers,
                Gas,
                Faults,
                HostResult,
            ],
            Self::HashPrecompile | Self::SignaturePrecompile | Self::CipherPrecompile => &[
                MemoryOrdering,
                Pointers,
                Precompile,
                Gas,
                Faults,
                HostResult,
            ],
            Self::GuestProofVerification => &[
                Pointers,
                GuestProofVerification,
                Gas,
                Faults,
                HostResult,
                StateEffect,
                StatementBinding,
            ],
            Self::Axt => &[
                Pointers,
                GuestProofVerification,
                Gas,
                Faults,
                HostResult,
                StateRead,
                StateEffect,
                StatementBinding,
            ],
            Self::HeapMemory => &[
                Initialization,
                MemoryOrdering,
                Pointers,
                Gas,
                Faults,
                HostResult,
            ],
            Self::TraceCommitment => &[
                MemoryOrdering,
                Pointers,
                Continuation,
                PrivateMasking,
                Gas,
                Faults,
                HostResult,
            ],
            Self::PrivateWitness => &[
                TypedValues,
                Pointers,
                Precompile,
                PrivateMasking,
                Gas,
                Faults,
                HostResult,
                StatementBinding,
            ],
            Self::PublicOutput => &[Gas, Faults, HostResult, StateEffect, StatementBinding],
            Self::NestedInvocation => &[
                TypedValues,
                Initialization,
                MemoryOrdering,
                Pointers,
                Calls,
                Copyback,
                VmRecursion,
                ProofComposition,
                Gas,
                Faults,
                HostResult,
                StateRead,
                StateEffect,
                StatementBinding,
            ],
        }
    }

    /// Host-state access classes `registered_syscall_access` may assign to a
    /// syscall of this relation class.
    #[must_use]
    pub const fn expected_access(self) -> &'static [SyscallAccess] {
        match self {
            Self::Terminal
            | Self::Diagnostic
            | Self::ExecutionContext
            | Self::TypedCodec
            | Self::Numeric
            | Self::HashPrecompile
            | Self::SignaturePrecompile
            | Self::CipherPrecompile
            | Self::HeapMemory
            | Self::TraceCommitment
            | Self::PrivateWitness => &[SyscallAccess::None],
            Self::LedgerEffect | Self::Axt => &[SyscallAccess::LedgerWrite],
            Self::ContractStateRead => &[SyscallAccess::StateRead],
            Self::ContractStateWrite => &[SyscallAccess::StateWrite],
            Self::LedgerQuery | Self::VrfEpochSeed => &[SyscallAccess::LedgerRead],
            Self::SoraCloud => &[SyscallAccess::LedgerRead, SyscallAccess::LedgerWrite],
            Self::GuestProofVerification => &[SyscallAccess::None, SyscallAccess::LedgerWrite],
            Self::PublicOutput
            | Self::NestedInvocation
            | Self::DynamicInstruction
            | Self::ContractEvent => &[SyscallAccess::Dynamic],
        }
    }
}

/// One ABI V1 syscall and the current state of its three proof bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallEntry {
    /// Canonical syscall number from `abi_syscall_list()`.
    pub number: u32,
    /// Canonical name from `syscall_name`.
    pub name: &'static str,
    /// Relation class.
    pub relation: SyscallRelation,
    /// Whether the relation binds the exact result registers and envelopes.
    pub result: CoverageStatus,
    /// Whether the relation binds every reachable trap of the syscall.
    pub trap: CoverageStatus,
    /// Whether the relation binds its reads, effects and context to the
    /// public statement.
    pub statement: CoverageStatus,
}

impl SyscallEntry {
    /// An inventoried syscall for which no proof code holds a relation.
    // TODO: Replace each binding with the status established by the complete
    // syscall relation as it lands (task M.2); never mark a binding covered
    // without equations exercised by a test.
    const fn uncovered(number: u32, constant: &'static str, relation: SyscallRelation) -> Self {
        Self {
            number,
            name: abi_name(constant),
            relation,
            result: CoverageStatus::Uncovered,
            trap: CoverageStatus::Uncovered,
            statement: CoverageStatus::Uncovered,
        }
    }

    /// Combined status: complete only when all three bindings are complete,
    /// uncovered only when none has a relation.
    #[must_use]
    pub const fn status(&self) -> CoverageStatus {
        match (self.result, self.trap, self.statement) {
            (CoverageStatus::Complete, CoverageStatus::Complete, CoverageStatus::Complete) => {
                CoverageStatus::Complete
            }
            (CoverageStatus::Uncovered, CoverageStatus::Uncovered, CoverageStatus::Uncovered) => {
                CoverageStatus::Uncovered
            }
            _ => CoverageStatus::ComponentOnly,
        }
    }
}

/// Strip the `SYSCALL_` prefix shared by every ABI constant identifier.
const fn abi_name(constant: &'static str) -> &'static str {
    const PREFIX: &str = "SYSCALL_";
    let bytes = constant.as_bytes();
    assert!(bytes.len() > PREFIX.len());
    let (prefix, name) = bytes.split_at(PREFIX.len());
    let mut index = 0;
    while index < PREFIX.len() {
        assert!(prefix[index] == PREFIX.as_bytes()[index]);
        index += 1;
    }
    match core::str::from_utf8(name) {
        Ok(name) => name,
        Err(_) => panic!("syscall constant names are ASCII"),
    }
}

macro_rules! sc {
    ($constant:ident, $relation:ident) => {
        SyscallEntry::uncovered(
            syscalls::$constant,
            stringify!($constant),
            SyscallRelation::$relation,
        )
    };
}

/// Number of ABI V1 syscalls.
pub const SYSCALL_COUNT: usize = 232;

/// Every ABI V1 syscall in ascending number order.
pub const SYSCALLS: &[SyscallEntry; SYSCALL_COUNT] = &[
    sc!(SYSCALL_DEBUG_PRINT, Diagnostic),
    sc!(SYSCALL_EXIT, Terminal),
    sc!(SYSCALL_ABORT, Terminal),
    sc!(SYSCALL_DEBUG_LOG, Diagnostic),
    sc!(SYSCALL_CONTRACT_ABORT, Terminal),
    sc!(SYSCALL_REGISTER_DOMAIN, LedgerEffect),
    sc!(SYSCALL_UNREGISTER_DOMAIN, LedgerEffect),
    sc!(SYSCALL_TRANSFER_DOMAIN, LedgerEffect),
    sc!(SYSCALL_REGISTER_ACCOUNT, LedgerEffect),
    sc!(SYSCALL_UNREGISTER_ACCOUNT, LedgerEffect),
    sc!(SYSCALL_REGISTER_PEER, LedgerEffect),
    sc!(SYSCALL_UNREGISTER_PEER, LedgerEffect),
    sc!(SYSCALL_ADD_SIGNATORY, LedgerEffect),
    sc!(SYSCALL_REMOVE_SIGNATORY, LedgerEffect),
    sc!(SYSCALL_SET_ACCOUNT_QUORUM, LedgerEffect),
    sc!(SYSCALL_SET_ACCOUNT_DETAIL, LedgerEffect),
    sc!(SYSCALL_REGISTER_ASSET, LedgerEffect),
    sc!(SYSCALL_UNREGISTER_ASSET, LedgerEffect),
    sc!(SYSCALL_MINT_ASSET, LedgerEffect),
    sc!(SYSCALL_BURN_ASSET, LedgerEffect),
    sc!(SYSCALL_TRANSFER_V1, LedgerEffect),
    sc!(SYSCALL_NFT_MINT_ASSET, LedgerEffect),
    sc!(SYSCALL_NFT_TRANSFER_ASSET, LedgerEffect),
    sc!(SYSCALL_NFT_SET_METADATA, LedgerEffect),
    sc!(SYSCALL_NFT_BURN_ASSET, LedgerEffect),
    sc!(SYSCALL_TRANSFER_V1_BATCH_BEGIN, LedgerEffect),
    sc!(SYSCALL_TRANSFER_V1_BATCH_END, LedgerEffect),
    sc!(SYSCALL_TRANSFER_V1_BATCH_APPLY, LedgerEffect),
    sc!(SYSCALL_TRANSFER_ASSET_SCOPED, LedgerEffect),
    sc!(SYSCALL_CREATE_ROLE, LedgerEffect),
    sc!(SYSCALL_DELETE_ROLE, LedgerEffect),
    sc!(SYSCALL_GRANT_ROLE, LedgerEffect),
    sc!(SYSCALL_REVOKE_ROLE, LedgerEffect),
    sc!(SYSCALL_GRANT_PERMISSION, LedgerEffect),
    sc!(SYSCALL_REVOKE_PERMISSION, LedgerEffect),
    sc!(SYSCALL_GRANT_CONTRACT_PERMISSION, LedgerEffect),
    sc!(SYSCALL_REVOKE_CONTRACT_PERMISSION, LedgerEffect),
    sc!(SYSCALL_CREATE_TRIGGER, LedgerEffect),
    sc!(SYSCALL_REMOVE_TRIGGER, LedgerEffect),
    sc!(SYSCALL_SET_TRIGGER_ENABLED, LedgerEffect),
    sc!(SYSCALL_DEACTIVATE_CONTRACT_INSTANCE, LedgerEffect),
    sc!(SYSCALL_REMOVE_SMART_CONTRACT_BYTES, LedgerEffect),
    sc!(SYSCALL_REGISTER_SMART_CONTRACT_CODE, LedgerEffect),
    sc!(SYSCALL_REGISTER_SMART_CONTRACT_BYTES, LedgerEffect),
    sc!(SYSCALL_ACTIVATE_CONTRACT_INSTANCE, LedgerEffect),
    sc!(SYSCALL_STATE_GET, ContractStateRead),
    sc!(SYSCALL_STATE_SET, ContractStateWrite),
    sc!(SYSCALL_STATE_DEL, ContractStateWrite),
    sc!(SYSCALL_BUILD_PATH_KEY_NORITO, TypedCodec),
    sc!(SYSCALL_JSON_ENCODE, TypedCodec),
    sc!(SYSCALL_JSON_DECODE, TypedCodec),
    sc!(SYSCALL_SCHEMA_ENCODE, TypedCodec),
    sc!(SYSCALL_SCHEMA_DECODE, TypedCodec),
    sc!(SYSCALL_SCHEMA_INFO, TypedCodec),
    sc!(SYSCALL_NAME_DECODE, TypedCodec),
    sc!(SYSCALL_POINTER_TO_NORITO, TypedCodec),
    sc!(SYSCALL_POINTER_FROM_NORITO, TypedCodec),
    sc!(SYSCALL_TLV_EQ, TypedCodec),
    sc!(SYSCALL_ZK_VOTE_VERIFY_BALLOT, GuestProofVerification),
    sc!(SYSCALL_ZK_VOTE_VERIFY_TALLY, GuestProofVerification),
    sc!(SYSCALL_ZK_ROOTS_GET, LedgerQuery),
    sc!(SYSCALL_ZK_VOTE_GET_TALLY, LedgerQuery),
    sc!(SYSCALL_ZK_VERIFY_BATCH, GuestProofVerification),
    sc!(SYSCALL_VRF_VERIFY, SignaturePrecompile),
    sc!(SYSCALL_VRF_VERIFY_BATCH, SignaturePrecompile),
    sc!(SYSCALL_TLV_LEN, TypedCodec),
    sc!(SYSCALL_JSON_GET_JSON, TypedCodec),
    sc!(SYSCALL_JSON_GET_NAME, TypedCodec),
    sc!(SYSCALL_JSON_GET_ACCOUNT_ID, TypedCodec),
    sc!(SYSCALL_JSON_GET_NFT_ID, TypedCodec),
    sc!(SYSCALL_JSON_GET_BLOB_HEX, TypedCodec),
    sc!(SYSCALL_VRF_EPOCH_SEED, VrfEpochSeed),
    sc!(SYSCALL_JSON_GET_ASSET_DEFINITION_ID, TypedCodec),
    sc!(SYSCALL_JSON_OBJECT, TypedCodec),
    sc!(SYSCALL_JSON_SET_I64, TypedCodec),
    sc!(SYSCALL_JSON_SET_ACCOUNT_ID, TypedCodec),
    sc!(SYSCALL_SM3_HASH, HashPrecompile),
    sc!(SYSCALL_SM2_VERIFY, SignaturePrecompile),
    sc!(SYSCALL_SM4_GCM_SEAL, CipherPrecompile),
    sc!(SYSCALL_SM4_GCM_OPEN, CipherPrecompile),
    sc!(SYSCALL_SM4_CCM_SEAL, CipherPrecompile),
    sc!(SYSCALL_SM4_CCM_OPEN, CipherPrecompile),
    sc!(SYSCALL_SHA256_HASH, HashPrecompile),
    sc!(SYSCALL_SHA3_HASH, HashPrecompile),
    sc!(SYSCALL_BLAKE2B256_HASH, HashPrecompile),
    sc!(SYSCALL_KECCAK256_HASH, HashPrecompile),
    sc!(SYSCALL_IROHA_HASH, HashPrecompile),
    sc!(
        SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
        DynamicInstruction
    ),
    sc!(SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, LedgerQuery),
    sc!(SYSCALL_CREATE_NFTS_FOR_ALL_USERS, DynamicInstruction),
    sc!(
        SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH,
        DynamicInstruction
    ),
    sc!(SYSCALL_GET_AUTHORITY, ExecutionContext),
    sc!(SYSCALL_SUBSCRIPTION_BILL, LedgerEffect),
    sc!(SYSCALL_SUBSCRIPTION_RECORD_USAGE, LedgerEffect),
    sc!(SYSCALL_RESOLVE_ACCOUNT_ALIAS, LedgerQuery),
    sc!(SYSCALL_CURRENT_TIME_MS, ExecutionContext),
    sc!(SYSCALL_CALL_CONTRACT, NestedInvocation),
    sc!(SYSCALL_EMIT_CONTRACT_EVENT, ContractEvent),
    sc!(SYSCALL_AXT_BEGIN, Axt),
    sc!(SYSCALL_AXT_TOUCH, Axt),
    sc!(SYSCALL_AXT_COMMIT, Axt),
    sc!(SYSCALL_VERIFY_DS_PROOF, Axt),
    sc!(SYSCALL_AXT_STAGE_ANCHORED_SPEND, Axt),
    sc!(SYSCALL_ESCROW_OPEN_OFFER, LedgerEffect),
    sc!(SYSCALL_ESCROW_ACCEPT, LedgerEffect),
    sc!(SYSCALL_ESCROW_MARK_PAYMENT_SENT, LedgerEffect),
    sc!(SYSCALL_ESCROW_RELEASE, LedgerEffect),
    sc!(SYSCALL_ESCROW_CANCEL, LedgerEffect),
    sc!(SYSCALL_ESCROW_OPEN_DISPUTE, LedgerEffect),
    sc!(SYSCALL_ESCROW_RESOLVE_DISPUTE, LedgerEffect),
    sc!(SYSCALL_SORACLOUD_READ_COMMITTED_STATE, SoraCloud),
    sc!(SYSCALL_SORACLOUD_EMIT_STATE_MUTATION, SoraCloud),
    sc!(SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE, SoraCloud),
    sc!(SYSCALL_SORACLOUD_APPEND_JOURNAL, SoraCloud),
    sc!(SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT, SoraCloud),
    sc!(SYSCALL_SORACLOUD_READ_CONFIG, SoraCloud),
    sc!(SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE, SoraCloud),
    sc!(SYSCALL_INPUT_PUBLISH_TLV, TypedCodec),
    sc!(SYSCALL_ALLOC, HeapMemory),
    sc!(SYSCALL_GET_PUBLIC_INPUT, ExecutionContext),
    sc!(SYSCALL_EXECUTION_SUMMARY, TraceCommitment),
    sc!(SYSCALL_GROW_HEAP, HeapMemory),
    sc!(SYSCALL_VERIFY_PROOF, GuestProofVerification),
    sc!(SYSCALL_GET_MERKLE_PATH, TraceCommitment),
    sc!(SYSCALL_PRIVATE_NUMERIC_VALCOM, PrivateWitness),
    sc!(SYSCALL_GET_ACCOUNT_BALANCE, LedgerQuery),
    sc!(SYSCALL_GET_MERKLE_COMPACT, TraceCommitment),
    sc!(SYSCALL_VERIFY_SIGNATURE, SignaturePrecompile),
    sc!(SYSCALL_GET_PRIVATE_INPUT, PrivateWitness),
    sc!(SYSCALL_COMMIT_OUTPUT, PublicOutput),
    sc!(SYSCALL_GET_REGISTER_MERKLE_COMPACT, TraceCommitment),
    sc!(SYSCALL_QUERY_EXECUTE_NORITO, LedgerQuery),
    sc!(SYSCALL_CORE_QUERY_GET, LedgerQuery),
    sc!(SYSCALL_CORE_QUERY_PAGE, LedgerQuery),
    sc!(SYSCALL_QUERY_GET_PARAMETER, LedgerQuery),
    sc!(SYSCALL_QUERY_GET_CONTRACT_MANIFEST, LedgerQuery),
    sc!(SYSCALL_QUERY_GET_CONTRACT_INSTANCE, LedgerQuery),
    sc!(SYSCALL_SYSVAR_CHAIN_ID, ExecutionContext),
    sc!(SYSCALL_SYSVAR_BLOCK_HEIGHT, ExecutionContext),
    sc!(SYSCALL_SYSVAR_BLOCK_TIME_MS, ExecutionContext),
    sc!(SYSCALL_SYSVAR_AUTHORITY, ExecutionContext),
    sc!(SYSCALL_SYSVAR_CONTRACT_ADDRESS, ExecutionContext),
    sc!(SYSCALL_SYSVAR_ENTRYPOINT, ExecutionContext),
    sc!(SYSCALL_DECODE_ARGUMENT_RECORD, TypedCodec),
    sc!(SYSCALL_SYSVAR_CONTRACT_SUBJECT, ExecutionContext),
    sc!(SYSCALL_NORMALIZE_NORITO_BYTES, TypedCodec),
    sc!(SYSCALL_STATE_HAS, ContractStateRead),
    sc!(SYSCALL_STATE_LEN, ContractStateRead),
    sc!(SYSCALL_STATE_COUNT, ContractStateRead),
    sc!(SYSCALL_STATE_MAP_KEY_AT, TypedCodec),
    sc!(SYSCALL_STATE_VALUE_ENCODE, TypedCodec),
    sc!(SYSCALL_STATE_VALUE_DECODE, TypedCodec),
    sc!(SYSCALL_STATE_PATH_FROM_NAME, TypedCodec),
    sc!(SYSCALL_STATE_SCAN, ContractStateRead),
    sc!(SYSCALL_JSON_BUILD, TypedCodec),
    sc!(SYSCALL_VALUE_ENCODE, TypedCodec),
    sc!(SYSCALL_BLOB_CONCAT, TypedCodec),
    sc!(SYSCALL_UTF8_VALIDATE, TypedCodec),
    sc!(SYSCALL_VALUE_TO_STRING, TypedCodec),
    sc!(SYSCALL_INT_FROM_I64, Numeric),
    sc!(SYSCALL_INT_FROM_U64, Numeric),
    sc!(SYSCALL_INT_TO_I64, Numeric),
    sc!(SYSCALL_INT_TO_U64, Numeric),
    sc!(SYSCALL_INT_NEG, Numeric),
    sc!(SYSCALL_INT_ADD, Numeric),
    sc!(SYSCALL_INT_SUB, Numeric),
    sc!(SYSCALL_INT_MUL, Numeric),
    sc!(SYSCALL_INT_DIV, Numeric),
    sc!(SYSCALL_INT_REM, Numeric),
    sc!(SYSCALL_INT_EQ, Numeric),
    sc!(SYSCALL_INT_NE, Numeric),
    sc!(SYSCALL_INT_LT, Numeric),
    sc!(SYSCALL_INT_LE, Numeric),
    sc!(SYSCALL_INT_GT, Numeric),
    sc!(SYSCALL_INT_GE, Numeric),
    sc!(SYSCALL_INT_WRAP_NEG, Numeric),
    sc!(SYSCALL_INT_WRAP_ADD, Numeric),
    sc!(SYSCALL_INT_WRAP_SUB, Numeric),
    sc!(SYSCALL_INT_WRAP_MUL, Numeric),
    sc!(SYSCALL_INT_ISQRT, Numeric),
    sc!(SYSCALL_INT_ABS, Numeric),
    sc!(SYSCALL_INT_MIN, Numeric),
    sc!(SYSCALL_INT_MAX, Numeric),
    sc!(SYSCALL_INT_DIV_CEIL, Numeric),
    sc!(SYSCALL_INT_GCD, Numeric),
    sc!(SYSCALL_INT_MEAN, Numeric),
    sc!(SYSCALL_DECIMAL_FROM_INT, Numeric),
    sc!(SYSCALL_DECIMAL_NEG, Numeric),
    sc!(SYSCALL_DECIMAL_ADD, Numeric),
    sc!(SYSCALL_DECIMAL_SUB, Numeric),
    sc!(SYSCALL_DECIMAL_MUL, Numeric),
    sc!(SYSCALL_DECIMAL_DIV_EXACT, Numeric),
    sc!(SYSCALL_DECIMAL_DIV_ROUND, Numeric),
    sc!(SYSCALL_DECIMAL_EQ, Numeric),
    sc!(SYSCALL_DECIMAL_NE, Numeric),
    sc!(SYSCALL_DECIMAL_LT, Numeric),
    sc!(SYSCALL_DECIMAL_LE, Numeric),
    sc!(SYSCALL_DECIMAL_GT, Numeric),
    sc!(SYSCALL_DECIMAL_GE, Numeric),
    sc!(SYSCALL_DECIMAL_TO_INT_EXACT, Numeric),
    sc!(SYSCALL_DECIMAL_TO_INT_TRUNC, Numeric),
    sc!(SYSCALL_DECIMAL_TO_INT_ROUND, Numeric),
    sc!(SYSCALL_DECIMAL_MUL_DIV_ROUND, Numeric),
    sc!(SYSCALL_QUANTITY_FROM_INT, Numeric),
    sc!(SYSCALL_QUANTITY_FROM_DECIMAL, Numeric),
    sc!(SYSCALL_QUANTITY_TO_DECIMAL, Numeric),
    sc!(SYSCALL_QUANTITY_ADD, Numeric),
    sc!(SYSCALL_QUANTITY_SUB, Numeric),
    sc!(SYSCALL_QUANTITY_MUL_DECIMAL, Numeric),
    sc!(SYSCALL_QUANTITY_DIV_DECIMAL_EXACT, Numeric),
    sc!(SYSCALL_QUANTITY_DIV_DECIMAL_ROUND, Numeric),
    sc!(SYSCALL_QUANTITY_RATIO_EXACT, Numeric),
    sc!(SYSCALL_QUANTITY_RATIO_ROUND, Numeric),
    sc!(SYSCALL_QUANTITY_EQ, Numeric),
    sc!(SYSCALL_QUANTITY_NE, Numeric),
    sc!(SYSCALL_QUANTITY_LT, Numeric),
    sc!(SYSCALL_QUANTITY_LE, Numeric),
    sc!(SYSCALL_QUANTITY_GT, Numeric),
    sc!(SYSCALL_QUANTITY_GE, Numeric),
    sc!(SYSCALL_QUANTITY_MUL_DIV_ROUND, Numeric),
    sc!(SYSCALL_JSON_GET_INT, TypedCodec),
    sc!(SYSCALL_JSON_GET_DECIMAL, TypedCodec),
    sc!(SYSCALL_JSON_GET_QUANTITY, TypedCodec),
    sc!(SYSCALL_JSON_GET_STRING, TypedCodec),
    sc!(SYSCALL_JSON_GET_BOOL, TypedCodec),
    sc!(SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY, LedgerEffect),
    sc!(SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT, LedgerEffect),
    sc!(SYSCALL_SET_ASSET_HOLDING_LIMIT, LedgerEffect),
    sc!(SYSCALL_ACCOUNT_RECOVERY_PROPOSE, LedgerEffect),
    sc!(SYSCALL_ACCOUNT_RECOVERY_APPROVE, LedgerEffect),
    sc!(SYSCALL_ACCOUNT_RECOVERY_CANCEL, LedgerEffect),
    sc!(SYSCALL_ACCOUNT_RECOVERY_FINALIZE, LedgerEffect),
];

// The table is binary-searched and compared with the sorted ABI list.
const _: () = {
    let mut index = 1;
    while index < SYSCALLS.len() {
        assert!(SYSCALLS[index - 1].number < SYSCALLS[index].number);
        index += 1;
    }
};

/// Return the inventory entry of one ABI V1 syscall.
#[must_use]
pub fn syscall_entry(number: u32) -> Option<&'static SyscallEntry> {
    SYSCALLS
        .binary_search_by_key(&number, |entry| entry.number)
        .ok()
        .map(|index| &SYSCALLS[index])
}

/// A host-private syscall number that is not part of ABI V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPrivateSyscall {
    /// Host-private syscall number.
    pub number: u32,
    /// Constant name without the `SYSCALL_` prefix.
    pub name: &'static str,
}

macro_rules! host_private {
    ($constant:ident) => {
        HostPrivateSyscall {
            number: syscalls::$constant,
            name: abi_name(stringify!($constant)),
        }
    };
}

/// Kotodama test-runner helpers outside `abi_syscall_list()`.
///
/// Production hosts reject them as `UnknownSyscall`; the relation must prove
/// that rejection and never a test-helper semantic.
pub const HOST_PRIVATE_SYSCALLS: &[HostPrivateSyscall] = &[
    host_private!(SYSCALL_KOTO_TEST_ACTOR_ACCOUNT),
    host_private!(SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY),
    host_private!(SYSCALL_KOTO_TEST_ACTOR_SIGN),
    host_private!(SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS),
    host_private!(SYSCALL_KOTO_TEST_EXPECT_REJECT_AS),
    host_private!(SYSCALL_KOTO_TEST_ASSERT_FAILED),
    host_private!(SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT),
    host_private!(SYSCALL_KOTO_TEST_ADVANCE_BLOCKS),
    host_private!(SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS),
    host_private!(SYSCALL_KOTO_TEST_CALL_SITE),
];
