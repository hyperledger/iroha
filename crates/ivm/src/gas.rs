//! Gas cost table and utilities for instruction gas accounting.
//!
//! Canonical schedule
//! - This table is the canonical source for gas costs used by the interpreter.
//!   Tests compare runtime accounting against this table to ensure conformance.
//! - Costs follow the IVM spec. Variants (e.g., DIV vs MUL) are distinguished by
//!   decoding full instruction words (funct fields), not just opcodes.
//!
//! Scope
//! - Includes extended vector/parallel and cryptographic instructions.
//! - Vector costs scale from the two-lane baseline by the deterministic logical
//!   vector length.
use crate::instruction::wide;
use iroha_crypto::Hash;
/// Gas accounting treats two lanes as the baseline for vector operations.
pub const VECTOR_BASE_LANES: usize = 2;
/// Default byte multiplier for syscall host-work gas families.
pub const SYSCALL_GAS_PER_BYTE: u64 = 1;
/// Version of the V1 direct signature-opcode byte gas formula.
pub const SIGNATURE_OPCODE_GAS_FORMULA_VERSION_V1: u64 = 1;
/// Gas charged for each payload byte consumed by a direct signature opcode.
pub const SIGNATURE_OPCODE_GAS_PER_PAYLOAD_BYTE: u64 = SYSCALL_GAS_PER_BYTE;
/// Fixed gas for `transfer_v1` FastPQ batch begin/end scope operations.
pub const G_FASTPQ_BATCH: u64 = 16;
/// Fixed gas for governance/admin contract-management bridge syscalls.
pub const G_CONTRACT_ADMIN: u64 = 16;
/// Fixed parent overhead for `CALL_CONTRACT`, before request/return byte charges.
pub const G_CALL_CONTRACT: u64 = 16;
/// Fixed gas for native asset escrow bridge syscalls.
pub const G_ESCROW: u64 = 16;
/// Fixed gas for Soracloud runtime syscalls, before request/response byte charges.
pub const G_SORACLOUD: u64 = 16;
/// Version of the consensus-visible host-syscall gas formulas.
pub const HOST_GAS_FORMULA_VERSION: u16 = 7;
/// Version of the V1 VRF base/item/byte gas formula.
pub const HOST_VRF_GAS_FORMULA_VERSION_V1: u64 = 1;
/// Version of the ledger-query base/item/offset/byte formula.
///
/// This value is included in the gas-schedule descriptor. Any change to the
/// formula, its charge-point ordering, or its sorted-query semantics MUST
/// increment it and regenerate the gas-schedule golden hash.
pub const LEDGER_QUERY_GAS_FORMULA_VERSION_V1: u64 = 1;
/// Fixed gas for a singular ledger query.
pub const LEDGER_QUERY_GAS_BASE_SINGULAR: u64 = 1_000;
/// Fixed gas for an iterable ledger query.
pub const LEDGER_QUERY_GAS_BASE_ITERABLE: u64 = 2_500;
/// Gas charged for each processed or directly skipped ledger-query item.
pub const LEDGER_QUERY_GAS_PER_ITEM: u64 = 250;
/// Multiplier applied to the item rate when a query requests sorting.
pub const LEDGER_QUERY_GAS_SORT_MULTIPLIER: u64 = 4;
/// Gas charged for each canonically measured query or projection byte.
pub const LEDGER_QUERY_GAS_PER_BYTE: u64 = 2;
/// Version of the bounded Ed25519 batch-verification gas formula.
pub const ED25519_BATCH_GAS_FORMULA_VERSION_V1: u64 = 1;
/// Gas charged for each encoded request byte before TLV hashing or Norito decoding.
pub const ED25519_BATCH_GAS_PER_PAYLOAD_BYTE: u64 = 1;
/// Gas charged before strictly verifying one Ed25519 batch entry.
pub const ED25519_BATCH_GAS_PER_ENTRY: u64 = 1_000;
/// Maximum entries accepted by one Ed25519 batch-verification instruction.
pub const ED25519_BATCH_MAX_ENTRIES: usize = 512;
/// Maximum encoded Norito request bytes accepted by batch verification.
pub const ED25519_BATCH_MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// Maximum elements in one nested sequence, including an entry message.
pub const ED25519_BATCH_MAX_SEQUENCE_ELEMENTS: usize = 64 * 1024;
/// Maximum total decoded elements across one batch request.
pub const ED25519_BATCH_MAX_TOTAL_ELEMENTS: usize = ED25519_BATCH_MAX_PAYLOAD_BYTES;
/// Maximum cumulative allocation permitted while decoding a batch request.
pub const ED25519_BATCH_MAX_DECODE_ALLOCATION_BYTES: usize = 2 * ED25519_BATCH_MAX_PAYLOAD_BYTES;
/// Maximum structural nesting depth accepted by a batch request.
pub const ED25519_BATCH_MAX_DECODE_DEPTH: usize = 8;
/// Decode budget for one attacker-authored Ed25519 batch request.
pub const ED25519_BATCH_DECODE_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    ED25519_BATCH_MAX_SEQUENCE_ELEMENTS,
    ED25519_BATCH_MAX_PAYLOAD_BYTES,
    ED25519_BATCH_MAX_TOTAL_ELEMENTS,
    ED25519_BATCH_MAX_DECODE_ALLOCATION_BYTES,
    ED25519_BATCH_MAX_DECODE_DEPTH,
);
/// Compute the V1 ledger-query charge from canonical schedule parameters.
///
/// `base` and `per_item` are selected before execution from the request kind
/// and whether sorting is requested. Unsorted offsets are charged directly;
/// sorted queries instead charge every scanned item at the multiplied rate.
#[must_use]
pub const fn ledger_query_gas_v1(
    base: u64,
    per_item: u64,
    offset_items: u64,
    processed_items: u64,
    processed_bytes: u64,
) -> u64 {
    base.saturating_add(per_item.saturating_mul(processed_items))
        .saturating_add(per_item.saturating_mul(offset_items))
        .saturating_add(LEDGER_QUERY_GAS_PER_BYTE.saturating_mul(processed_bytes))
}
/// Compute gas that must be reserved before Ed25519 batch request work.
///
/// The fixed opcode base is charged by [`cost_of`]. This function covers the
/// complete request bytes and every strict per-entry verification.
#[must_use]
pub const fn ed25519_batch_extra_gas(payload_bytes: u64, entries: u64) -> u64 {
    ED25519_BATCH_GAS_PER_PAYLOAD_BYTE
        .saturating_mul(payload_bytes)
        .saturating_add(ED25519_BATCH_GAS_PER_ENTRY.saturating_mul(entries))
}
/// Compute the byte-linear surcharge for one direct signature opcode.
///
/// Aliased operands are charged independently because the opcode validates
/// each message, signature, and public-key TLV independently.
#[must_use]
pub fn signature_opcode_extra_gas(
    message_bytes: u64,
    signature_bytes: u64,
    public_key_bytes: u64,
) -> Option<u64> {
    message_bytes
        .checked_add(signature_bytes)?
        .checked_add(public_key_bytes)?
        .checked_mul(SIGNATURE_OPCODE_GAS_PER_PAYLOAD_BYTE)
}
/// Fixed durable-state syscall charge before path, value, scan, or response bytes.
pub const STATE_QUERY_GAS_BASE: u64 = 16;
/// Charge for visiting one durable-state key in an ordered scan.
pub const STATE_SCAN_ITEM_GAS: u64 = 1;
/// Fixed charge for one guest heap allocation.
pub const ALLOCATION_GAS_BASE: u64 = 1;
/// Allocation granularity used by the pointer ABI.
pub const ALLOCATION_GAS_WORD_BYTES: u64 = 8;
/// Generic conservative host quote base.
pub const CONSERVATIVE_SYSCALL_GAS_BASE: u64 = 4_096;
/// Generic conservative multiplier for public syscall input bytes.
pub const CONSERVATIVE_SYSCALL_INPUT_MULTIPLIER: u64 = 64;
/// Generic conservative multiplier for complete host output regions.
pub const CONSERVATIVE_SYSCALL_RESPONSE_MULTIPLIER: u64 = 4;
/// Fixed `GROW_HEAP` charge.
pub const GROW_HEAP_GAS_BASE: u64 = 16;
/// `GROW_HEAP` charge per logical page.
pub const GROW_HEAP_GAS_PER_PAGE: u64 = 16;
/// Logical page size used by `GROW_HEAP` metering.
pub const GROW_HEAP_PAGE_BYTES: u64 = 4_096;
/// Common base charge for byte-linear local host helpers.
pub const HOST_BYTE_GAS_BASE: u64 = 16;
/// Common base charge for cryptographic verification helpers.
pub const HOST_VERIFY_GAS_BASE: u64 = 64;
/// Fixed charge for canonical V1 VRF request handling.
pub const HOST_VRF_VERIFY_GAS_BASE: u64 = 64;
/// Charge for each VRF item whose validation begins.
pub const HOST_VRF_VERIFY_GAS_PER_ITEM: u64 = 250_000;
/// Charge per byte in the complete canonical VRF request frame.
pub const HOST_VRF_VERIFY_GAS_PER_BYTE: u64 = 5;
/// Compute the V1 VRF charge from canonical schedule parameters.
///
/// Decode and batch-bound failures examine zero items. An item rejected during
/// chain, variant, key, proof, or pairing validation counts as examined.
#[must_use]
pub const fn vrf_verify_gas(examined_items: u64, payload_bytes: u64) -> u64 {
    HOST_VRF_VERIFY_GAS_BASE
        .saturating_add(HOST_VRF_VERIFY_GAS_PER_ITEM.saturating_mul(examined_items))
        .saturating_add(HOST_VRF_VERIFY_GAS_PER_BYTE.saturating_mul(payload_bytes))
}
/// Schema codec base charge.
pub const HOST_SCHEMA_GAS_BASE: u64 = 32;
/// Debug/abort/exit fixed host charge.
pub const HOST_DEBUG_GAS_BASE: u64 = 16;
/// Output commitment fixed host charge.
pub const HOST_COMMIT_OUTPUT_GAS: u64 = 16;
/// Charge per committed byte in the written prefix of the output region.
pub const HOST_COMMIT_OUTPUT_GAS_PER_BYTE: u64 = SYSCALL_GAS_PER_BYTE;
/// Private-input retrieval fixed host charge.
///
/// This maximum-size quote is debited before outer Norito decoding, canonical
/// numeric validation, envelope serialization, or private HEAP allocation.
pub const HOST_PRIVATE_INPUT_GAS: u64 = 2_048;
/// Full-width typed private numeric Pedersen commitment charge.
///
/// The quote covers two maximum-size opaque TLV validations, two domain-separated projections,
/// scalar reductions, and one full compressed BLS12-381 commitment before public output allocation.
pub const HOST_PRIVATE_NUMERIC_VALCOM_GAS: u64 = 50_000;
/// Maximum pointer payload accepted by response-producing codec helpers.
pub const HOST_CODEC_MAX_INPUT_BYTES: usize = 32 * 1024;
/// Maximum guest-visible payload emitted by response-producing codec helpers.
pub const HOST_CODEC_MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// Fixed charge for each proof submitted to a ZK verification syscall.
///
/// This matches the V1 confidential-verification baseline while keeping IVM
/// syscall accounting immutable and bound by [`schedule_hash`].
pub const HOST_ZK_VERIFY_GAS_PER_PROOF: u64 = 250_000;
/// Default charge for one canonical public-input unit.
pub const HOST_ZK_VERIFY_GAS_PER_PUBLIC_INPUT: u64 = 2_000;
/// Charge per encoded request byte processed by a ZK verification syscall.
pub const HOST_ZK_VERIFY_GAS_PER_BYTE: u64 = 5;
/// Version of the canonical ZK syscall gas schedule snapshot.
pub const HOST_ZK_GAS_SCHEDULE_VERSION: u16 = 1;
/// Hard V1 cap for a single ZK envelope or an encoded batch request.
pub const HOST_ZK_VERIFY_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Hard V1 cap for proofs in one ZK batch syscall.
pub const HOST_ZK_VERIFY_MAX_BATCH_PROOFS: usize = 16;
/// Bytes in one canonical field-element-sized public-input unit.
pub const HOST_ZK_VERIFY_PUBLIC_INPUT_UNIT_BYTES: u32 = 32;
/// Fixed bytes in the hashed batch status TLV, excluding status bytes.
pub const HOST_ZK_VERIFY_BATCH_OUTPUT_FIXED_BYTES: u64 = 87;
/// Encoded status bytes emitted for each proof in a batch.
pub const HOST_ZK_VERIFY_BATCH_OUTPUT_BYTES_PER_PROOF: u64 = 1;
const ZK_GAS_SCHEDULE_DOMAIN_V1: &[u8] = b"iroha.ivm.zk-gas-schedule.v1";
/// Immutable consensus snapshot used to meter ZK verification syscalls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkGasScheduleV1 {
    /// Fixed cost paid for every backend verification attempt.
    pub proof_base: u64,
    /// Cost for each canonical public-input unit.
    pub per_public_input: u64,
    /// Cost for each request, proof, or output byte processed.
    pub per_proof_byte: u64,
    /// Maximum encoded single envelope or batch archive length.
    pub max_payload_bytes: u64,
    /// Maximum proofs admitted in one batch.
    pub max_batch_proofs: u32,
    /// Bytes represented by one public-input unit.
    pub public_input_unit_bytes: u32,
    /// Fixed bytes in the canonical hashed batch response.
    pub batch_output_fixed_bytes: u64,
    /// Response bytes emitted for each batch status.
    pub batch_output_bytes_per_proof: u64,
}
impl ZkGasScheduleV1 {
    /// Construct a V1 schedule using configured rates and fixed ABI caps/layout.
    #[must_use]
    pub const fn from_rates(proof_base: u64, per_public_input: u64, per_proof_byte: u64) -> Self {
        Self {
            proof_base,
            per_public_input,
            per_proof_byte,
            max_payload_bytes: HOST_ZK_VERIFY_MAX_PAYLOAD_BYTES as u64,
            max_batch_proofs: HOST_ZK_VERIFY_MAX_BATCH_PROOFS as u32,
            public_input_unit_bytes: HOST_ZK_VERIFY_PUBLIC_INPUT_UNIT_BYTES,
            batch_output_fixed_bytes: HOST_ZK_VERIFY_BATCH_OUTPUT_FIXED_BYTES,
            batch_output_bytes_per_proof: HOST_ZK_VERIFY_BATCH_OUTPUT_BYTES_PER_PROOF,
        }
    }
    /// Return the consensus subhash of this complete schedule snapshot.
    #[must_use]
    pub fn hash(self) -> Hash {
        let mut bytes = Vec::with_capacity(ZK_GAS_SCHEDULE_DOMAIN_V1.len() + 2 + 8 * 6 + 4 * 2);
        bytes.extend_from_slice(ZK_GAS_SCHEDULE_DOMAIN_V1);
        bytes.extend_from_slice(&HOST_ZK_GAS_SCHEDULE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.proof_base.to_le_bytes());
        bytes.extend_from_slice(&self.per_public_input.to_le_bytes());
        bytes.extend_from_slice(&self.per_proof_byte.to_le_bytes());
        bytes.extend_from_slice(&self.max_payload_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.max_batch_proofs.to_le_bytes());
        bytes.extend_from_slice(&self.public_input_unit_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.batch_output_fixed_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.batch_output_bytes_per_proof.to_le_bytes());
        Hash::new(bytes)
    }
    /// Return the exact encoded byte bound for a batch response.
    #[must_use]
    pub fn batch_output_bytes(self, proof_count: usize) -> u64 {
        self.batch_output_fixed_bytes.saturating_add(
            self.batch_output_bytes_per_proof
                .saturating_mul(u64::try_from(proof_count).unwrap_or(u64::MAX)),
        )
    }
    /// Convert public-input bytes to canonical field-element-sized units.
    #[must_use]
    pub fn public_input_count(self, public_input_bytes: usize) -> u64 {
        let unit = u64::from(self.public_input_unit_bytes.max(1));
        u64::try_from(public_input_bytes)
            .unwrap_or(u64::MAX)
            .div_ceil(unit)
    }
    fn gas(self, proof_count: usize, metered_bytes: u64, public_input_count: u64) -> u64 {
        self.proof_base
            .saturating_mul(u64::try_from(proof_count).unwrap_or(u64::MAX))
            .saturating_add(self.per_proof_byte.saturating_mul(metered_bytes))
            .saturating_add(self.per_public_input.saturating_mul(public_input_count))
    }
    /// Conservative single-envelope quote derived before decoding.
    #[must_use]
    pub fn conservative_single_gas(self, payload_bytes: usize) -> u64 {
        self.gas(
            1,
            u64::try_from(payload_bytes).unwrap_or(u64::MAX),
            self.public_input_count(payload_bytes),
        )
    }
    /// Actual single-envelope cost after authenticated public-input decoding.
    #[must_use]
    pub fn actual_single_gas(self, payload_bytes: usize, public_input_bytes: usize) -> u64 {
        self.gas(
            1,
            u64::try_from(payload_bytes).unwrap_or(u64::MAX),
            self.public_input_count(public_input_bytes),
        )
    }
    /// Conservative batch quote derived before decoding.
    #[must_use]
    pub fn conservative_batch_gas(self, proof_count: usize, payload_bytes: usize) -> u64 {
        let rounding_allowance = u64::try_from(proof_count).unwrap_or(u64::MAX);
        let public_inputs = self
            .public_input_count(payload_bytes)
            .saturating_add(rounding_allowance);
        self.gas(
            proof_count,
            u64::try_from(payload_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(self.batch_output_bytes(proof_count)),
            public_inputs,
        )
    }
    /// Actual batch cost after authenticated public-input decoding.
    #[must_use]
    pub fn actual_batch_gas(
        self,
        proof_count: usize,
        payload_bytes: usize,
        public_input_count: u64,
    ) -> u64 {
        self.gas(
            proof_count,
            u64::try_from(payload_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(self.batch_output_bytes(proof_count)),
            public_input_count,
        )
    }
}
impl Default for ZkGasScheduleV1 {
    fn default() -> Self {
        Self::from_rates(
            HOST_ZK_VERIFY_GAS_PER_PROOF,
            HOST_ZK_VERIFY_GAS_PER_PUBLIC_INPUT,
            HOST_ZK_VERIFY_GAS_PER_BYTE,
        )
    }
}
/// Deterministic syscall gas for a fixed family plus request/response bytes.
#[must_use]
pub fn syscall_byte_gas(base: u64, request_bytes: usize, response_bytes: usize) -> u64 {
    let bytes = u64::try_from(request_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(response_bytes).unwrap_or(u64::MAX));
    base.saturating_add(SYSCALL_GAS_PER_BYTE.saturating_mul(bytes))
}
/// Deterministic gas for committing the written prefix of the output region.
#[must_use]
pub fn commit_output_gas(output_bytes: u64) -> u64 {
    HOST_COMMIT_OUTPUT_GAS
        .saturating_add(HOST_COMMIT_OUTPUT_GAS_PER_BYTE.saturating_mul(output_bytes))
}
/// Deterministic gas for one ZK verification request.
#[must_use]
pub fn zk_verify_gas(payload_bytes: usize) -> u64 {
    ZkGasScheduleV1::default().conservative_single_gas(payload_bytes)
}
/// Deterministic gas for a ZK batch request.
///
/// The request bytes cover archive validation and decoding. Each proof pays a separate verification
/// base plus the bounded archive/status material created while dispatching the batch.
#[must_use]
pub fn zk_verify_batch_gas(proof_count: usize, payload_bytes: usize) -> u64 {
    ZkGasScheduleV1::default().conservative_batch_gas(proof_count, payload_bytes)
}
/// Scale a vector opcode's base cost by the actual logical lane count.
pub(crate) fn scaled_vector_cost(base_cost: u64, vector_len: usize) -> u64 {
    let lanes = vector_len.max(1) as u64;
    base_cost
        .saturating_mul(lanes)
        .div_ceil(VECTOR_BASE_LANES as u64)
}
/// Canonical opcode set covered by the gas schedule.
///
/// Keep this list in opcode order so `schedule_hash` remains deterministic across platforms.
pub const SCHEDULE_OPCODES: &[u8] = &[
    // Arithmetic + logic
    wide::arithmetic::ADD,
    wide::arithmetic::SUB,
    wide::arithmetic::AND,
    wide::arithmetic::OR,
    wide::arithmetic::XOR,
    wide::arithmetic::SLL,
    wide::arithmetic::SRL,
    wide::arithmetic::SRA,
    wide::arithmetic::NEG,
    wide::arithmetic::NOT,
    wide::arithmetic::ADDI,
    wide::arithmetic::ANDI,
    wide::arithmetic::ORI,
    wide::arithmetic::XORI,
    wide::arithmetic::MUL,
    wide::arithmetic::MULH,
    wide::arithmetic::MULHU,
    wide::arithmetic::MULHSU,
    wide::arithmetic::DIV,
    wide::arithmetic::DIVU,
    wide::arithmetic::REM,
    wide::arithmetic::REMU,
    wide::arithmetic::ROTL,
    wide::arithmetic::ROTR,
    wide::arithmetic::ROTL_IMM,
    wide::arithmetic::ROTR_IMM,
    wide::arithmetic::POPCNT,
    wide::arithmetic::CLZ,
    wide::arithmetic::CTZ,
    wide::arithmetic::ISQRT,
    wide::arithmetic::MIN,
    wide::arithmetic::MAX,
    wide::arithmetic::ABS,
    wide::arithmetic::DIV_CEIL,
    wide::arithmetic::GCD,
    wide::arithmetic::MEAN,
    wide::arithmetic::SLT,
    wide::arithmetic::SLTU,
    wide::arithmetic::SEQ,
    wide::arithmetic::SNE,
    wide::arithmetic::CMOV,
    wide::arithmetic::CMOVI,
    // Memory
    wide::memory::LOAD64,
    wide::memory::STORE64,
    wide::memory::LOAD128,
    wide::memory::STORE128,
    wide::memory::LDLIT,
    wide::memory::LDI64,
    // Control flow
    wide::control::BEQ,
    wide::control::BNE,
    wide::control::BLT,
    wide::control::BGE,
    wide::control::BLTU,
    wide::control::BGEU,
    wide::control::JAL,
    wide::control::JALR,
    wide::control::JR,
    wide::control::JMP,
    wide::control::JALS,
    wide::control::HALT,
    // System
    wide::system::SCALL,
    wide::system::GETGAS,
    wide::system::SYSTEM,
    // Crypto/vector
    wide::crypto::VADD32,
    wide::crypto::VADD64,
    wide::crypto::VAND,
    wide::crypto::VXOR,
    wide::crypto::VOR,
    wide::crypto::VROT32,
    wide::crypto::SETVL,
    wide::crypto::PARBEGIN,
    wide::crypto::PAREND,
    wide::crypto::SHA256BLOCK,
    wide::crypto::SHA3BLOCK,
    wide::crypto::POSEIDON2,
    wide::crypto::POSEIDON6,
    wide::crypto::AESENC,
    wide::crypto::AESDEC,
    wide::crypto::BLAKE2S,
    wide::crypto::ED25519VERIFY,
    wide::crypto::ED25519BATCHVERIFY,
    wide::crypto::ECDSAVERIFY,
    wide::crypto::DILITHIUMVERIFY,
    // ZK helpers
    wide::zk::ASSERT,
    wide::zk::ASSERT_EQ,
    wide::zk::FADD,
    wide::zk::FSUB,
    wide::zk::FMUL,
    wide::zk::FINV,
    wide::zk::ASSERT_RANGE,
];
/// Return the gas cost for the given 32-bit instruction word.
///
/// Property tests in `crates/ivm/tests/gas_property.rs` exercise representative
/// instruction sequences to ensure runtime accounting matches this schedule.
// See roadmap.md → Spec → Implementation Plan (Folded) → Opcode + Gas Reference is normative.
pub fn cost_of(instr: u32) -> Option<u64> {
    let wide_op = wide::opcode(instr);
    match wide_op {
        wide::arithmetic::ADD
        | wide::arithmetic::SUB
        | wide::arithmetic::AND
        | wide::arithmetic::OR
        | wide::arithmetic::XOR
        | wide::arithmetic::SLL
        | wide::arithmetic::SRL
        | wide::arithmetic::SRA
        | wide::arithmetic::NEG
        | wide::arithmetic::NOT
        | wide::arithmetic::ADDI
        | wide::arithmetic::ANDI
        | wide::arithmetic::ORI
        | wide::arithmetic::XORI => Some(1),
        wide::arithmetic::MUL
        | wide::arithmetic::MULH
        | wide::arithmetic::MULHU
        | wide::arithmetic::MULHSU => Some(3),
        wide::arithmetic::DIV
        | wide::arithmetic::DIVU
        | wide::arithmetic::REM
        | wide::arithmetic::REMU => Some(10),
        wide::arithmetic::ROTL
        | wide::arithmetic::ROTR
        | wide::arithmetic::ROTL_IMM
        | wide::arithmetic::ROTR_IMM => Some(2),
        wide::arithmetic::POPCNT
        | wide::arithmetic::CLZ
        | wide::arithmetic::CTZ
        | wide::arithmetic::ISQRT => Some(6),
        wide::arithmetic::MIN | wide::arithmetic::MAX | wide::arithmetic::ABS => Some(1),
        wide::arithmetic::DIV_CEIL | wide::arithmetic::GCD => Some(12),
        wide::arithmetic::MEAN => Some(2),
        wide::arithmetic::SLT | wide::arithmetic::SLTU => Some(2),
        wide::arithmetic::SEQ | wide::arithmetic::SNE => Some(2),
        wide::arithmetic::CMOV | wide::arithmetic::CMOVI => Some(3),
        wide::memory::LDLIT | wide::memory::LDI64 => Some(1),
        wide::memory::LOAD64 | wide::memory::STORE64 => Some(3),
        wide::memory::LOAD128 | wide::memory::STORE128 => Some(5),
        wide::control::BEQ
        | wide::control::BNE
        | wide::control::BLT
        | wide::control::BGE
        | wide::control::BLTU
        | wide::control::BGEU => Some(1),
        wide::control::JAL
        | wide::control::JALR
        | wide::control::JR
        | wide::control::JMP
        | wide::control::JALS => Some(2),
        wide::control::HALT => Some(0),
        wide::system::SCALL | wide::system::SYSTEM => Some(5),
        wide::system::GETGAS => Some(0),
        wide::crypto::VADD32 | wide::crypto::VADD64 => Some(2),
        wide::crypto::VAND | wide::crypto::VXOR | wide::crypto::VOR | wide::crypto::VROT32 => {
            Some(1)
        }
        wide::crypto::SETVL => Some(1),
        wide::crypto::PARBEGIN | wide::crypto::PAREND => Some(0),
        wide::crypto::SHA256BLOCK | wide::crypto::SHA3BLOCK => Some(50),
        wide::crypto::POSEIDON2 | wide::crypto::POSEIDON6 => Some(10),
        wide::crypto::AESENC | wide::crypto::AESDEC => Some(30),
        wide::crypto::BLAKE2S => Some(40),
        wide::crypto::ED25519VERIFY => Some(1000),
        wide::crypto::ED25519BATCHVERIFY => Some(500),
        wide::crypto::ECDSAVERIFY => Some(1500),
        wide::crypto::DILITHIUMVERIFY => Some(5000),
        wide::zk::ASSERT | wide::zk::ASSERT_EQ | wide::zk::ASSERT_RANGE => Some(1),
        wide::zk::FADD | wide::zk::FSUB => Some(1),
        wide::zk::FMUL => Some(3),
        wide::zk::FINV => Some(5),
        _ => None,
    }
}
/// Maximum base cost across all scheduled opcodes.
#[must_use]
pub fn max_instruction_cost() -> u64 {
    SCHEDULE_OPCODES
        .iter()
        .map(|op| cost_of((*op as u32) << 24).expect("scheduled opcode must have gas cost"))
        .max()
        .unwrap_or(0)
}
/// Compute gas cost when the base cost and opcode were already extracted.
pub(crate) fn cost_from_parts(
    base_cost: Option<u64>,
    wide_op: u8,
    vector_len: usize,
) -> Option<u64> {
    let mut cost = base_cost?;
    if matches!(
        wide_op,
        wide::crypto::VADD32
            | wide::crypto::VADD64
            | wide::crypto::VAND
            | wide::crypto::VXOR
            | wide::crypto::VOR
            | wide::crypto::VROT32
    ) {
        cost = scaled_vector_cost(cost, vector_len);
    }
    Some(cost)
}
/// Compute gas cost using the supplied deterministic logical vector length.
pub fn cost_of_with_vector_len(instr: u32, vector_len: usize) -> Option<u64> {
    let wide_op = wide::opcode(instr);
    cost_from_parts(cost_of(instr), wide_op, vector_len)
}
const GAS_SCHEDULE_DOMAIN: &str = "iroha.ivm.gas-schedule.v4";
const GAS_SCHEDULE_DESCRIPTOR_VERSION: u16 = 4;
#[derive(Clone, Debug, PartialEq, Eq)]
struct GasParameter {
    name: &'static str,
    value: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SyscallMeteringRecord {
    number: u32,
    metering: u8,
    gas_class: u8,
    quote_strategy: u8,
    formula: u8,
    parameters: u8,
    minimum_gas: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SyscallMeteringPhaseRecord {
    name: &'static str,
    tag: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct GasScheduleDescriptor {
    domain: &'static str,
    version: u16,
    opcodes: Vec<(u8, u64)>,
    parameters: Vec<GasParameter>,
    staged_phases: Vec<SyscallMeteringPhaseRecord>,
    syscalls: Vec<SyscallMeteringRecord>,
}
fn canonical_gas_parameters() -> Vec<GasParameter> {
    let vrf_decode_limits = ivm_abi::host_payload::VRF_VERIFY_DECODE_LIMITS_V1;
    let values = [
        (
            "call_table_formula_version",
            crate::call_gas::FORMULA_VERSION,
        ),
        ("call_table_per_byte", crate::call_gas::PER_BYTE),
        ("call_schema_node", crate::call_gas::NODE),
        ("call_pointer_base", crate::call_gas::POINTER_BASE),
        ("call_bitmap_coverage", crate::call_gas::BITMAP_COVERAGE),
        ("call_word_bytes", ivm_abi::call::CALL_WORD_BYTES_V1 as u64),
        ("vector_base_lanes", VECTOR_BASE_LANES as u64),
        ("syscall_per_byte", SYSCALL_GAS_PER_BYTE),
        (
            "signature_opcode_formula_version",
            SIGNATURE_OPCODE_GAS_FORMULA_VERSION_V1,
        ),
        (
            "signature_opcode_per_payload_byte",
            SIGNATURE_OPCODE_GAS_PER_PAYLOAD_BYTE,
        ),
        ("fastpq_batch_base", G_FASTPQ_BATCH),
        ("contract_admin_base", G_CONTRACT_ADMIN),
        ("call_contract_base", G_CALL_CONTRACT),
        ("escrow_base", G_ESCROW),
        ("soracloud_base", G_SORACLOUD),
        ("host_formula_version", u64::from(HOST_GAS_FORMULA_VERSION)),
        (
            "ledger_query_formula_version",
            LEDGER_QUERY_GAS_FORMULA_VERSION_V1,
        ),
        ("ledger_query_base_singular", LEDGER_QUERY_GAS_BASE_SINGULAR),
        ("ledger_query_base_iterable", LEDGER_QUERY_GAS_BASE_ITERABLE),
        ("ledger_query_per_item", LEDGER_QUERY_GAS_PER_ITEM),
        (
            "ledger_query_sort_multiplier",
            LEDGER_QUERY_GAS_SORT_MULTIPLIER,
        ),
        ("ledger_query_per_byte", LEDGER_QUERY_GAS_PER_BYTE),
        (
            "ed25519_batch_formula_version",
            ED25519_BATCH_GAS_FORMULA_VERSION_V1,
        ),
        (
            "ed25519_batch_per_payload_byte",
            ED25519_BATCH_GAS_PER_PAYLOAD_BYTE,
        ),
        ("ed25519_batch_per_entry", ED25519_BATCH_GAS_PER_ENTRY),
        (
            "ed25519_batch_max_entries",
            ED25519_BATCH_MAX_ENTRIES as u64,
        ),
        (
            "ed25519_batch_max_payload_bytes",
            ED25519_BATCH_MAX_PAYLOAD_BYTES as u64,
        ),
        (
            "ed25519_batch_decode_max_sequence_elements",
            ED25519_BATCH_MAX_SEQUENCE_ELEMENTS as u64,
        ),
        (
            "ed25519_batch_decode_max_field_bytes",
            ED25519_BATCH_MAX_PAYLOAD_BYTES as u64,
        ),
        (
            "ed25519_batch_decode_max_total_elements",
            ED25519_BATCH_MAX_TOTAL_ELEMENTS as u64,
        ),
        (
            "ed25519_batch_decode_max_total_allocated_bytes",
            ED25519_BATCH_MAX_DECODE_ALLOCATION_BYTES as u64,
        ),
        (
            "ed25519_batch_decode_max_nesting_depth",
            ED25519_BATCH_MAX_DECODE_DEPTH as u64,
        ),
        (
            "numeric_formula_version",
            crate::numeric_gas::NUMERIC_GAS_FORMULA_VERSION_V1,
        ),
        ("numeric_entry", crate::numeric_gas::NUMERIC_ENTRY_GAS),
        (
            "numeric_per_limb_work",
            crate::numeric_gas::NUMERIC_GAS_PER_LIMB_WORK,
        ),
        (
            "numeric_validation_word_bytes",
            crate::numeric_gas::NUMERIC_VALIDATION_WORD_BYTES,
        ),
        (
            "numeric_pointer_header_bytes",
            crate::numeric_gas::POINTER_HEADER_BYTES,
        ),
        (
            "numeric_pointer_hash_bytes",
            crate::numeric_gas::POINTER_HASH_BYTES,
        ),
        (
            "numeric_max_decimal_scale",
            u64::from(crate::numeric_gas::MAX_DECIMAL_SCALE),
        ),
        (
            "numeric_max_product_scale",
            u64::from(crate::numeric_gas::MAX_PRODUCT_SCALE),
        ),
        (
            "numeric_max_value_limbs",
            crate::numeric_gas::MAX_VALUE_LIMBS,
        ),
        (
            "numeric_max_product_limbs",
            crate::numeric_gas::MAX_PRODUCT_LIMBS,
        ),
        ("state_query_base", STATE_QUERY_GAS_BASE),
        ("state_scan_item", STATE_SCAN_ITEM_GAS),
        ("state_path_per_byte", SYSCALL_GAS_PER_BYTE),
        ("state_value_per_byte", SYSCALL_GAS_PER_BYTE),
        ("state_page_per_byte", SYSCALL_GAS_PER_BYTE),
        ("allocation_base", ALLOCATION_GAS_BASE),
        ("allocation_word_bytes", ALLOCATION_GAS_WORD_BYTES),
        ("conservative_base", CONSERVATIVE_SYSCALL_GAS_BASE),
        (
            "conservative_input_multiplier",
            CONSERVATIVE_SYSCALL_INPUT_MULTIPLIER,
        ),
        (
            "conservative_response_multiplier",
            CONSERVATIVE_SYSCALL_RESPONSE_MULTIPLIER,
        ),
        ("grow_heap_base", GROW_HEAP_GAS_BASE),
        ("grow_heap_per_page", GROW_HEAP_GAS_PER_PAGE),
        ("grow_heap_page_bytes", GROW_HEAP_PAGE_BYTES),
        ("host_byte_base", HOST_BYTE_GAS_BASE),
        ("host_verify_base", HOST_VERIFY_GAS_BASE),
        ("host_vrf_formula_version", HOST_VRF_GAS_FORMULA_VERSION_V1),
        ("host_vrf_verify_base", HOST_VRF_VERIFY_GAS_BASE),
        ("host_vrf_verify_per_item", HOST_VRF_VERIFY_GAS_PER_ITEM),
        ("host_vrf_verify_per_byte", HOST_VRF_VERIFY_GAS_PER_BYTE),
        (
            "host_vrf_verify_max_payload_bytes",
            ivm_abi::host_payload::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1 as u64,
        ),
        (
            "host_vrf_verify_max_batch_items",
            ivm_abi::host_payload::MAX_VRF_VERIFY_BATCH_ITEMS_V1 as u64,
        ),
        (
            "host_vrf_decode_max_sequence_elements",
            vrf_decode_limits.max_sequence_elements() as u64,
        ),
        (
            "host_vrf_decode_max_field_bytes",
            vrf_decode_limits.max_field_bytes() as u64,
        ),
        (
            "host_vrf_decode_max_total_elements",
            vrf_decode_limits.max_total_elements() as u64,
        ),
        (
            "host_vrf_decode_max_total_allocated_bytes",
            vrf_decode_limits.max_total_allocated_bytes() as u64,
        ),
        (
            "host_vrf_decode_max_nesting_depth",
            vrf_decode_limits.max_nesting_depth() as u64,
        ),
        ("host_schema_base", HOST_SCHEMA_GAS_BASE),
        ("host_debug_base", HOST_DEBUG_GAS_BASE),
        ("host_commit_output", HOST_COMMIT_OUTPUT_GAS),
        (
            "host_commit_output_per_byte",
            HOST_COMMIT_OUTPUT_GAS_PER_BYTE,
        ),
        ("host_private_input", HOST_PRIVATE_INPUT_GAS),
        (
            "host_private_numeric_valcom",
            HOST_PRIVATE_NUMERIC_VALCOM_GAS,
        ),
        (
            "host_codec_max_input_bytes",
            HOST_CODEC_MAX_INPUT_BYTES as u64,
        ),
        (
            "host_codec_max_output_bytes",
            HOST_CODEC_MAX_OUTPUT_BYTES as u64,
        ),
        ("host_zk_verify_per_proof", HOST_ZK_VERIFY_GAS_PER_PROOF),
        (
            "host_zk_verify_per_public_input",
            HOST_ZK_VERIFY_GAS_PER_PUBLIC_INPUT,
        ),
        ("host_zk_verify_per_byte", HOST_ZK_VERIFY_GAS_PER_BYTE),
        (
            "host_zk_gas_schedule_version",
            u64::from(HOST_ZK_GAS_SCHEDULE_VERSION),
        ),
        (
            "host_zk_verify_max_payload_bytes",
            HOST_ZK_VERIFY_MAX_PAYLOAD_BYTES as u64,
        ),
        (
            "host_zk_verify_max_batch_proofs",
            HOST_ZK_VERIFY_MAX_BATCH_PROOFS as u64,
        ),
        (
            "host_zk_verify_public_input_unit_bytes",
            u64::from(HOST_ZK_VERIFY_PUBLIC_INPUT_UNIT_BYTES),
        ),
        (
            "host_zk_verify_batch_output_fixed_bytes",
            HOST_ZK_VERIFY_BATCH_OUTPUT_FIXED_BYTES,
        ),
        (
            "host_zk_verify_batch_output_per_proof",
            HOST_ZK_VERIFY_BATCH_OUTPUT_BYTES_PER_PROOF,
        ),
        (
            "memory_input_region_bytes",
            crate::memory::Memory::INPUT_SIZE,
        ),
        (
            "memory_output_region_bytes",
            crate::memory::Memory::OUTPUT_SIZE,
        ),
        (
            "state_scan_max_items_v1",
            crate::syscalls::STATE_SCAN_MAX_ITEMS_V1,
        ),
        (
            "state_max_path_bytes",
            crate::syscalls::STATE_MAX_PATH_BYTES as u64,
        ),
        (
            "state_max_path_frame_bytes",
            crate::syscalls::STATE_MAX_PATH_FRAME_BYTES as u64,
        ),
        (
            "state_max_value_bytes",
            crate::syscalls::STATE_MAX_VALUE_BYTES as u64,
        ),
        (
            "state_map_max_key_bytes",
            crate::syscalls::STATE_MAP_MAX_KEY_BYTES as u64,
        ),
        (
            "state_map_max_base_bytes",
            crate::syscalls::STATE_MAP_MAX_BASE_BYTES as u64,
        ),
        (
            "state_map_max_base_frame_bytes",
            crate::syscalls::STATE_MAP_MAX_BASE_FRAME_BYTES as u64,
        ),
        (
            "state_map_max_page_bytes",
            crate::syscalls::STATE_MAP_MAX_PAGE_BYTES as u64,
        ),
    ];
    let mut parameters: Vec<_> = values
        .into_iter()
        .map(|(name, value)| GasParameter { name, value })
        .collect();
    let zk_schedule_hash: [u8; 32] = ZkGasScheduleV1::default().hash().into();
    let hash_parameter_names = [
        "host_zk_schedule_hash_word_0",
        "host_zk_schedule_hash_word_1",
        "host_zk_schedule_hash_word_2",
        "host_zk_schedule_hash_word_3",
    ];
    parameters.extend(
        hash_parameter_names
            .into_iter()
            .zip(zk_schedule_hash.chunks_exact(8))
            .map(|(name, chunk)| GasParameter {
                name,
                value: u64::from_le_bytes(
                    chunk
                        .try_into()
                        .expect("32-byte hash consists of four complete u64 words"),
                ),
            }),
    );
    parameters
}
fn metering_tag(metering: crate::syscall_metering::SyscallMetering) -> u8 {
    match metering {
        crate::syscall_metering::SyscallMetering::Reserved => 0,
        crate::syscall_metering::SyscallMetering::Staged => 1,
    }
}
fn gas_class_tag(class: crate::host::HostSyscallGasClass) -> u8 {
    match class {
        crate::host::HostSyscallGasClass::VmLocal => 0,
        crate::host::HostSyscallGasClass::Allocation => 1,
        crate::host::HostSyscallGasClass::DurableStateRead => 2,
        crate::host::HostSyscallGasClass::DurableStateWrite => 3,
        crate::host::HostSyscallGasClass::LedgerRead => 4,
        crate::host::HostSyscallGasClass::LedgerWrite => 5,
        crate::host::HostSyscallGasClass::Dynamic => 6,
    }
}
fn quote_strategy_tag(strategy: crate::host::HostSyscallQuoteStrategy) -> u8 {
    match strategy {
        crate::host::HostSyscallQuoteStrategy::InputOutputBounded => 0,
        crate::host::HostSyscallQuoteStrategy::AllocationExtent => 1,
        crate::host::HostSyscallQuoteStrategy::ReserveAvailable => 2,
    }
}
fn formula_tag(formula: crate::host::HostSyscallGasFormula) -> u8 {
    use crate::host::HostSyscallGasFormula as Formula;
    match formula {
        Formula::NumericStaged => 13,
        Formula::ByteLinear => 0,
        Formula::VerifyByteLinear => 1,
        Formula::SchemaByteLinear => 2,
        Formula::AllocationExtent => 3,
        Formula::GrowHeapPages => 4,
        Formula::CommitOutput => 5,
        Formula::StateGet => 6,
        Formula::StatePath => 7,
        Formula::StateValue => 8,
        Formula::StateCount => 10,
        Formula::ReserveAvailable => 11,
        Formula::ConservativeEnvelope => 12,
        Formula::ZkVerifyV1 => 14,
        Formula::LedgerQueryV1 => 15,
        Formula::VrfVerifyV1 => 16,
        Formula::StateScan => 17,
    }
}
fn parameters_tag(parameters: crate::host::HostSyscallGasParameters) -> u8 {
    use crate::host::HostSyscallGasParameters as Parameters;
    match parameters {
        Parameters::Numeric => 8,
        Parameters::HostByte => 0,
        Parameters::HostVerify => 1,
        Parameters::HostSchema => 2,
        Parameters::Allocation => 3,
        Parameters::GrowHeap => 4,
        Parameters::HostCommit => 5,
        Parameters::DurableState => 6,
        Parameters::Conservative => 7,
        Parameters::ZkVerifyV1 => 9,
        Parameters::LedgerQueryV1 => 10,
        Parameters::VrfVerifyV1 => 11,
    }
}
fn canonical_gas_schedule_descriptor() -> GasScheduleDescriptor {
    let opcodes = SCHEDULE_OPCODES
        .iter()
        .map(|&opcode| {
            let instruction = u32::from(opcode) << 24;
            (
                opcode,
                cost_of(instruction).expect("scheduled opcode must have gas cost"),
            )
        })
        .collect();
    let syscalls = crate::host::abi_v1_host_syscall_metering_registry()
        .iter()
        .map(|spec| SyscallMeteringRecord {
            number: spec.number,
            metering: metering_tag(spec.metering),
            gas_class: gas_class_tag(spec.gas_class),
            quote_strategy: quote_strategy_tag(spec.quote_strategy),
            formula: formula_tag(spec.formula),
            parameters: parameters_tag(spec.parameters),
            minimum_gas: spec.minimum_gas,
        })
        .collect();
    let staged_phases = crate::syscall_metering::SyscallMeteringPhase::ALL
        .into_iter()
        .map(|phase| SyscallMeteringPhaseRecord {
            name: phase.descriptor_name(),
            tag: phase.tag(),
        })
        .collect();
    GasScheduleDescriptor {
        domain: GAS_SCHEDULE_DOMAIN,
        version: GAS_SCHEDULE_DESCRIPTOR_VERSION,
        opcodes,
        parameters: canonical_gas_parameters(),
        staged_phases,
        syscalls,
    }
}
fn push_field(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buffer.extend_from_slice(bytes);
}
fn encode_gas_schedule_descriptor(descriptor: &GasScheduleDescriptor) -> Vec<u8> {
    let mut buffer = Vec::new();
    push_field(&mut buffer, descriptor.domain.as_bytes());
    buffer.extend_from_slice(&descriptor.version.to_le_bytes());
    buffer.extend_from_slice(&(descriptor.opcodes.len() as u64).to_le_bytes());
    for (opcode, cost) in &descriptor.opcodes {
        buffer.push(*opcode);
        buffer.extend_from_slice(&cost.to_le_bytes());
    }
    buffer.extend_from_slice(&(descriptor.parameters.len() as u64).to_le_bytes());
    for parameter in &descriptor.parameters {
        push_field(&mut buffer, parameter.name.as_bytes());
        buffer.extend_from_slice(&parameter.value.to_le_bytes());
    }
    buffer.extend_from_slice(&(descriptor.staged_phases.len() as u64).to_le_bytes());
    for phase in &descriptor.staged_phases {
        push_field(&mut buffer, phase.name.as_bytes());
        buffer.push(phase.tag);
    }
    buffer.extend_from_slice(&(descriptor.syscalls.len() as u64).to_le_bytes());
    for syscall in &descriptor.syscalls {
        buffer.extend_from_slice(&syscall.number.to_le_bytes());
        buffer.push(syscall.metering);
        buffer.push(syscall.gas_class);
        buffer.push(syscall.quote_strategy);
        buffer.push(syscall.formula);
        buffer.push(syscall.parameters);
        buffer.extend_from_slice(&syscall.minimum_gas.to_le_bytes());
    }
    buffer
}
/// Deterministic digest of the canonical gas schedule.
///
/// The descriptor binds the opcode-cost table, every named formula parameter, every staged-metering
/// phase name/tag, and the exhaustive ABI-v1 syscall metering registry so validators can assert the
/// active schedule matches consensus configuration.
#[must_use]
pub fn schedule_hash() -> Hash {
    Hash::new(encode_gas_schedule_descriptor(
        &canonical_gas_schedule_descriptor(),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor_hash(descriptor: &GasScheduleDescriptor) -> Hash {
        Hash::new(encode_gas_schedule_descriptor(descriptor))
    }
    fn assert_descriptor_mutation_changes_hash(mutator: impl FnOnce(&mut GasScheduleDescriptor)) {
        let canonical = canonical_gas_schedule_descriptor();
        let canonical_hash = descriptor_hash(&canonical);
        let mut changed = canonical;
        mutator(&mut changed);
        assert_ne!(descriptor_hash(&changed), canonical_hash);
    }
    #[test]
    fn schedule_hash_binds_domain_version_opcode_order_and_costs() {
        let canonical = canonical_gas_schedule_descriptor();
        assert_eq!(descriptor_hash(&canonical), schedule_hash());
        assert_descriptor_mutation_changes_hash(|changed| changed.domain = "wrong-domain");
        assert_descriptor_mutation_changes_hash(|changed| changed.version += 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.opcodes[0].0 ^= 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.opcodes[0].1 += 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.opcodes.swap(0, 1));
    }
    #[test]
    fn schedule_hash_binds_every_named_host_formula_parameter_and_order() {
        let canonical = canonical_gas_schedule_descriptor();
        assert!(!canonical.parameters.is_empty());
        for index in 0..canonical.parameters.len() {
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.parameters[index].value = changed.parameters[index].value.wrapping_add(1);
            });
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.parameters[index].name = "mutated_parameter";
            });
        }
        assert_descriptor_mutation_changes_hash(|changed| changed.parameters.swap(0, 1));
    }
    #[test]
    fn schedule_hash_binds_the_complete_live_ledger_query_formula() {
        let expected = [
            (
                "ledger_query_formula_version",
                LEDGER_QUERY_GAS_FORMULA_VERSION_V1,
            ),
            ("ledger_query_base_singular", LEDGER_QUERY_GAS_BASE_SINGULAR),
            ("ledger_query_base_iterable", LEDGER_QUERY_GAS_BASE_ITERABLE),
            ("ledger_query_per_item", LEDGER_QUERY_GAS_PER_ITEM),
            (
                "ledger_query_sort_multiplier",
                LEDGER_QUERY_GAS_SORT_MULTIPLIER,
            ),
            ("ledger_query_per_byte", LEDGER_QUERY_GAS_PER_BYTE),
        ];
        let canonical = canonical_gas_schedule_descriptor();
        for (name, value) in expected {
            let matches = canonical
                .parameters
                .iter()
                .enumerate()
                .filter(|(_, parameter)| parameter.name == name)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "descriptor coverage for {name}");
            let (index, parameter) = matches[0];
            assert_eq!(parameter.value, value, "descriptor value for {name}");
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.parameters[index].value = changed.parameters[index].value.wrapping_add(1);
            });
        }
        assert_eq!(
            ledger_query_gas_v1(
                LEDGER_QUERY_GAS_BASE_ITERABLE,
                LEDGER_QUERY_GAS_PER_ITEM,
                3,
                2,
                100,
            ),
            3_950,
        );
    }
    #[test]
    fn schedule_hash_binds_the_complete_live_ed25519_batch_formula() {
        let expected = [
            (
                "ed25519_batch_formula_version",
                ED25519_BATCH_GAS_FORMULA_VERSION_V1,
            ),
            (
                "ed25519_batch_per_payload_byte",
                ED25519_BATCH_GAS_PER_PAYLOAD_BYTE,
            ),
            ("ed25519_batch_per_entry", ED25519_BATCH_GAS_PER_ENTRY),
            (
                "ed25519_batch_max_entries",
                ED25519_BATCH_MAX_ENTRIES as u64,
            ),
            (
                "ed25519_batch_max_payload_bytes",
                ED25519_BATCH_MAX_PAYLOAD_BYTES as u64,
            ),
            (
                "ed25519_batch_decode_max_sequence_elements",
                ED25519_BATCH_DECODE_LIMITS.max_sequence_elements() as u64,
            ),
            (
                "ed25519_batch_decode_max_field_bytes",
                ED25519_BATCH_DECODE_LIMITS.max_field_bytes() as u64,
            ),
            (
                "ed25519_batch_decode_max_total_elements",
                ED25519_BATCH_DECODE_LIMITS.max_total_elements() as u64,
            ),
            (
                "ed25519_batch_decode_max_total_allocated_bytes",
                ED25519_BATCH_DECODE_LIMITS.max_total_allocated_bytes() as u64,
            ),
            (
                "ed25519_batch_decode_max_nesting_depth",
                ED25519_BATCH_DECODE_LIMITS.max_nesting_depth() as u64,
            ),
        ];
        let canonical = canonical_gas_schedule_descriptor();
        for (name, value) in expected {
            let matches = canonical
                .parameters
                .iter()
                .enumerate()
                .filter(|(_, parameter)| parameter.name == name)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "descriptor coverage for {name}");
            let (index, parameter) = matches[0];
            assert_eq!(parameter.value, value, "descriptor value for {name}");
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.parameters[index].value = changed.parameters[index].value.wrapping_add(1);
            });
        }
        assert_eq!(
            ed25519_batch_extra_gas(123, 2),
            123 * ED25519_BATCH_GAS_PER_PAYLOAD_BYTE + 2 * ED25519_BATCH_GAS_PER_ENTRY,
        );
    }
    #[test]
    fn schedule_hash_binds_the_complete_live_signature_opcode_formula() {
        let expected = [
            (
                "signature_opcode_formula_version",
                SIGNATURE_OPCODE_GAS_FORMULA_VERSION_V1,
            ),
            (
                "signature_opcode_per_payload_byte",
                SIGNATURE_OPCODE_GAS_PER_PAYLOAD_BYTE,
            ),
        ];
        let canonical = canonical_gas_schedule_descriptor();
        for (name, value) in expected {
            let matches = canonical
                .parameters
                .iter()
                .enumerate()
                .filter(|(_, parameter)| parameter.name == name)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "descriptor coverage for {name}");
            let (index, parameter) = matches[0];
            assert_eq!(parameter.value, value, "descriptor value for {name}");
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.parameters[index].value = changed.parameters[index].value.wrapping_add(1);
            });
        }
        assert_eq!(signature_opcode_extra_gas(11, 64, 32), Some(107));
        assert_eq!(signature_opcode_extra_gas(u64::MAX, 1, 0), None);
    }
    #[test]
    fn schedule_hash_binds_the_complete_live_vrf_formula() {
        let decode_limits = ivm_abi::host_payload::VRF_VERIFY_DECODE_LIMITS_V1;
        let expected = [
            ("host_vrf_formula_version", HOST_VRF_GAS_FORMULA_VERSION_V1),
            ("host_vrf_verify_base", HOST_VRF_VERIFY_GAS_BASE),
            ("host_vrf_verify_per_item", HOST_VRF_VERIFY_GAS_PER_ITEM),
            ("host_vrf_verify_per_byte", HOST_VRF_VERIFY_GAS_PER_BYTE),
            (
                "host_vrf_verify_max_payload_bytes",
                ivm_abi::host_payload::MAX_VRF_VERIFY_PAYLOAD_BYTES_V1 as u64,
            ),
            (
                "host_vrf_verify_max_batch_items",
                ivm_abi::host_payload::MAX_VRF_VERIFY_BATCH_ITEMS_V1 as u64,
            ),
            (
                "host_vrf_decode_max_sequence_elements",
                decode_limits.max_sequence_elements() as u64,
            ),
            (
                "host_vrf_decode_max_field_bytes",
                decode_limits.max_field_bytes() as u64,
            ),
            (
                "host_vrf_decode_max_total_elements",
                decode_limits.max_total_elements() as u64,
            ),
            (
                "host_vrf_decode_max_total_allocated_bytes",
                decode_limits.max_total_allocated_bytes() as u64,
            ),
            (
                "host_vrf_decode_max_nesting_depth",
                decode_limits.max_nesting_depth() as u64,
            ),
        ];
        let canonical = canonical_gas_schedule_descriptor();
        for (name, value) in expected {
            let matches = canonical
                .parameters
                .iter()
                .enumerate()
                .filter(|(_, parameter)| parameter.name == name)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "descriptor coverage for {name}");
            let (index, parameter) = matches[0];
            assert_eq!(parameter.value, value, "descriptor value for {name}");
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.parameters[index].value = changed.parameters[index].value.wrapping_add(1);
            });
        }
        assert_eq!(vrf_verify_gas(2, 100), 500_564);
    }
    #[test]
    fn schedule_hash_binds_vrf_syscalls_to_the_vrf_formula_family() {
        let canonical = canonical_gas_schedule_descriptor();
        for number in [
            crate::syscalls::SYSCALL_VRF_VERIFY,
            crate::syscalls::SYSCALL_VRF_VERIFY_BATCH,
        ] {
            let matches = canonical
                .syscalls
                .iter()
                .enumerate()
                .filter(|(_, syscall)| syscall.number == number)
                .collect::<Vec<_>>();
            assert_eq!(
                matches.len(),
                1,
                "metering descriptor coverage for VRF syscall {number:#x}"
            );
            let (index, syscall) = matches[0];
            assert_eq!(syscall.quote_strategy, 0);
            assert_eq!(syscall.formula, 16);
            assert_eq!(syscall.parameters, 11);
            assert_eq!(syscall.minimum_gas, vrf_verify_gas(1, 0));
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.syscalls[index].formula ^= 0x80;
            });
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.syscalls[index].parameters ^= 0x80;
            });
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.syscalls[index].minimum_gas =
                    changed.syscalls[index].minimum_gas.wrapping_add(1);
            });
        }
    }
    #[test]
    fn schedule_hash_binds_every_ledger_query_syscall_to_its_formula_family() {
        let canonical = canonical_gas_schedule_descriptor();
        for number in [
            crate::syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY,
            crate::syscalls::SYSCALL_QUERY_EXECUTE_NORITO,
            crate::syscalls::SYSCALL_CORE_QUERY_GET,
            crate::syscalls::SYSCALL_CORE_QUERY_PAGE,
            crate::syscalls::SYSCALL_QUERY_GET_PARAMETER,
            crate::syscalls::SYSCALL_QUERY_GET_CONTRACT_MANIFEST,
            crate::syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE,
            crate::syscalls::SYSCALL_GET_ACCOUNT_BALANCE,
            crate::syscalls::SYSCALL_ASSET_UID_HOLDING_QUOTE,
            crate::syscalls::SYSCALL_ASSET_FI_LINK_REVISION,
            crate::syscalls::SYSCALL_ASSET_SAME_UID,
            crate::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS,
        ] {
            let matches = canonical
                .syscalls
                .iter()
                .enumerate()
                .filter(|(_, syscall)| syscall.number == number)
                .collect::<Vec<_>>();
            assert_eq!(
                matches.len(),
                1,
                "metering descriptor coverage for ledger-query syscall {number:#x}"
            );
            let (index, syscall) = matches[0];
            assert_eq!(syscall.quote_strategy, 2);
            assert_eq!(syscall.formula, 15);
            assert_eq!(syscall.parameters, 10);
            assert_eq!(syscall.minimum_gas, LEDGER_QUERY_GAS_BASE_SINGULAR);
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.syscalls[index].formula ^= 0x80;
            });
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.syscalls[index].parameters ^= 0x80;
            });
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.syscalls[index].minimum_gas =
                    changed.syscalls[index].minimum_gas.wrapping_add(1);
            });
        }
    }
    #[test]
    fn schedule_hash_binds_every_staged_metering_phase_name_tag_and_order() {
        let canonical = canonical_gas_schedule_descriptor();
        assert_eq!(
            canonical.staged_phases.len(),
            crate::syscall_metering::SyscallMeteringPhase::COUNT
        );
        for (index, phase) in canonical.staged_phases.iter().enumerate() {
            assert_eq!(usize::from(phase.tag), index);
            assert_eq!(
                phase.name,
                crate::syscall_metering::SyscallMeteringPhase::ALL[index].descriptor_name()
            );
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.staged_phases[index].name = "MutatedPhase";
            });
            assert_descriptor_mutation_changes_hash(|changed| {
                changed.staged_phases[index].tag ^= 0x80;
            });
        }
        assert_descriptor_mutation_changes_hash(|changed| changed.staged_phases.swap(0, 1));
        assert_descriptor_mutation_changes_hash(|changed| {
            let _ = changed.staged_phases.pop();
        });
    }
    #[test]
    fn schedule_hash_binds_exhaustive_syscall_metering_records() {
        let canonical = canonical_gas_schedule_descriptor();
        assert_eq!(
            canonical.syscalls.len(),
            crate::syscalls::abi_syscall_list().len()
        );
        assert!(
            canonical
                .syscalls
                .windows(2)
                .all(|pair| pair[0].number < pair[1].number)
        );
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].number += 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].metering ^= 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].gas_class ^= 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].quote_strategy ^= 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].formula ^= 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].parameters ^= 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls[0].minimum_gas += 1);
        assert_descriptor_mutation_changes_hash(|changed| changed.syscalls.swap(0, 1));
        assert_descriptor_mutation_changes_hash(|changed| {
            let _ = changed.syscalls.pop();
        });
    }
    #[test]
    fn zk_verification_gas_scales_with_every_proof_and_encoded_byte() {
        assert_eq!(
            zk_verify_gas(7),
            HOST_ZK_VERIFY_GAS_PER_PROOF
                + HOST_ZK_VERIFY_GAS_PER_PUBLIC_INPUT
                + 7 * HOST_ZK_VERIFY_GAS_PER_BYTE
        );
        let one = zk_verify_batch_gas(1, 100);
        let two = zk_verify_batch_gas(2, 100);
        assert_eq!(
            two - one,
            HOST_ZK_VERIFY_GAS_PER_PROOF
                + HOST_ZK_VERIFY_GAS_PER_PUBLIC_INPUT
                + HOST_ZK_VERIFY_GAS_PER_BYTE
        );
        assert_eq!(
            zk_verify_batch_gas(2, 101) - two,
            HOST_ZK_VERIFY_GAS_PER_BYTE
        );
        assert_eq!(
            zk_verify_batch_gas(2, 129) - zk_verify_batch_gas(2, 128),
            HOST_ZK_VERIFY_GAS_PER_BYTE + HOST_ZK_VERIFY_GAS_PER_PUBLIC_INPUT
        );
        assert_eq!(zk_verify_batch_gas(usize::MAX, usize::MAX), u64::MAX);
    }
    #[test]
    fn zk_batch_output_bound_matches_canonical_hashed_tlv() {
        let schedule = ZkGasScheduleV1::default();
        for count in [1_usize, 2, 16] {
            let body = norito::to_bytes(&vec![0_u8; count]).expect("encode status vector");
            let complete_tlv_bytes = 7 + body.len() + iroha_crypto::Hash::LENGTH;
            assert_eq!(
                u64::try_from(complete_tlv_bytes).expect("bounded response length"),
                schedule.batch_output_bytes(count),
                "count={count}"
            );
            assert_eq!(schedule.batch_output_bytes(count), 87 + count as u64);
        }
    }
    #[test]
    fn zk_schedule_subhash_binds_every_rate_cap_and_layout_field() {
        let canonical = ZkGasScheduleV1::default();
        let canonical_hash = canonical.hash();
        let changed = [
            ZkGasScheduleV1 {
                proof_base: canonical.proof_base + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                per_public_input: canonical.per_public_input + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                per_proof_byte: canonical.per_proof_byte + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                max_payload_bytes: canonical.max_payload_bytes + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                max_batch_proofs: canonical.max_batch_proofs + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                public_input_unit_bytes: canonical.public_input_unit_bytes + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                batch_output_fixed_bytes: canonical.batch_output_fixed_bytes + 1,
                ..canonical
            },
            ZkGasScheduleV1 {
                batch_output_bytes_per_proof: canonical.batch_output_bytes_per_proof + 1,
                ..canonical
            },
        ];
        assert!(
            changed
                .into_iter()
                .all(|schedule| schedule.hash() != canonical_hash)
        );
    }
    #[test]
    fn cost_from_parts_matches_full_cost_path() {
        for &op in SCHEDULE_OPCODES {
            let instr = u32::from(op) << 24;
            for vector_len in [0, 1, 2, 4, 16] {
                assert_eq!(
                    cost_from_parts(cost_of(instr), op, vector_len),
                    cost_of_with_vector_len(instr, vector_len),
                    "op=0x{op:02x} vector_len={vector_len}",
                );
            }
        }
    }
}
