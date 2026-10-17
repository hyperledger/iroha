//! Algebraic trace material for the word-oriented SHA-256 STARK segments.
//!
//! The native word circuit is compiled into one verifier-fixed local schedule
//! and one global word-memory permutation:
//!
//! - every non-operation word definition has a 32-bit range row;
//! - sigma rows carry exact input/output bits;
//! - choice and majority use four eight-bit chunks with constrained running
//!   recomposition;
//! - additions constrain all operands, the output, and the three-bit carry;
//! - local word references and definitions feed a four-lane product tree;
//! - the same tuples feed execution/address-sorted memory products;
//! - all twenty-three physical continuation fields are materialized.
//!
//! The standalone builder retains the exact logical row count. The aggregate adapter embeds its two
//! physical `2^19` slots vertically in the common `2^20` native domain and pads every unused row
//! algebraically. This is deliberate: byte-copy and call-bus terminals may only be joined when they
//! share the same subgroup and masking polynomial.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::credential_pre_aux::ZkX509CredentialPreAuxBindingV1;
#[cfg(test)]
use super::sha256_word_air::derive_sha256_word_memory_challenges_v1;
use super::{
    der_limits::ZK_X509_DER_MAX_DOCUMENT_BYTES_V1,
    private_table::{PrivateTableV1, zeroize_field_rows_v1},
    sha256_word_air::{
        SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1, SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1,
        SigmaThirdV1, WORD_MEMORY_PERMUTATION_LANES_V1, WordIdV1, WordMemoryAccessV1,
        WordOperationV1, ZkX509Sha256WordAirErrorV1, ZkX509Sha256WordCircuitV1,
        ZkX509WordMemoryChallengesV1, ZkX509WordMemoryLaneChallengesV1,
        build_sha256_word_circuit_v1,
    },
};
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_MODULUS_V1, GoldilocksFieldV1 as F, PolynomialAirFieldV1, TransparentStarkErrorV1,
    TransparentTranscriptV1,
};
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use thiserror::Error;
pub const SHA_WORD_BASE_WIDTH_V1: usize = 64;
pub const SHA_WORD_COPY_LANES_V1: usize = WORD_MEMORY_PERMUTATION_LANES_V1;
pub const SHA_WORD_LOCAL_PRODUCT_WIDTH_V1: usize = 6 * SHA_WORD_COPY_LANES_V1;
pub const SHA_WORD_MEMORY_PRODUCT_WIDTH_V1: usize = 4 * SHA_WORD_COPY_LANES_V1;
pub const SHA_WORD_CONTINUATION_WIDTH_V1: usize = 7 + 4 * SHA_WORD_COPY_LANES_V1;
pub const SHA_WORD_AUX_WIDTH_V1: usize =
    SHA_WORD_LOCAL_PRODUCT_WIDTH_V1 + SHA_WORD_CONTINUATION_WIDTH_V1 + SHA_WORD_COPY_LANES_V1;
/// Canonical common native domain used by the aggregate proof.
pub const SHA_WORD_AGGREGATE_TRACE_LOG2_V1: u8 = 20;
/// Canonical common native row count used by the aggregate proof.
pub const SHA_WORD_AGGREGATE_TRACE_SIZE_V1: usize = 1 << SHA_WORD_AGGREGATE_TRACE_LOG2_V1;
/// Native row count of each of the two vertical logical SHA slots.
pub const SHA_WORD_LOGICAL_SLOT_LOG2_V1: u8 = 19;
/// Native row count of each of the two vertical logical SHA slots.
pub const SHA_WORD_LOGICAL_SLOT_ROWS_V1: usize = 1 << SHA_WORD_LOGICAL_SLOT_LOG2_V1;
/// Verifier-preprocessed numeric fixed width used by the aggregate STARK.
pub const SHA_WORD_STARK_FIXED_WIDTH_V1: usize = 55;
/// Exact number of base-only errors folded after the base commitment.
pub const SHA_WORD_STARK_BASE_ERROR_COUNT_V1: usize = 441;
/// Exact fixed-width residue vector used by the aggregate STARK.
pub const SHA_WORD_STARK_CONSTRAINT_COUNT_V1: usize = 155;
/// Maximum algebraic degree over committed and verifier-fixed columns.
#[cfg(test)]
pub const SHA_WORD_STARK_CONSTRAINT_DEGREE_V1: u8 = 4;
/// Fixed-capacity SHA call base width.  The twelve extra columns carry the
/// private active/final-block selectors, sorted-memory adjacency selector,
/// per-byte message/marker masks, and the selected digest-memory address.
pub const SHA_WORD_CAPACITY_BASE_WIDTH_V1: usize = 76;
/// Fixed-capacity SHA call auxiliary width before the cross-adapter call bus. The three extra
/// columns carry the private message-byte count, padding phase, and active-block count.
pub const SHA_WORD_CAPACITY_AUX_WIDTH_V1: usize = 54;
/// Verifier-derived fixed width for one fixed-capacity SHA call before the
/// call identity and physical-segment columns are appended.
pub const SHA_WORD_CAPACITY_FIXED_WIDTH_V1: usize = 72;
/// Capacity controls beyond the 155 raw word-AIR residues: selectors/masks (40), inactive-row folds
/// (8), block controls (6), count/padding/digest controls (28), inactive local products (20),
/// memory controls (47), and zeroed continuation cells (31).
const SHA_WORD_CAPACITY_CONTROL_CONSTRAINT_COUNT_V1: usize = 180;
/// Exact residue width of the fixed-capacity word relation.
pub const SHA_WORD_CAPACITY_CONSTRAINT_COUNT_V1: usize =
    SHA_WORD_STARK_CONSTRAINT_COUNT_V1 + SHA_WORD_CAPACITY_CONTROL_CONSTRAINT_COUNT_V1;
/// Maximum total degree, including private activity and verifier-fixed selectors.
///
/// Both the ordinary padding equation (degree-four gate times a degree-two
/// byte/mask product) and the Boolean operation's first event pair (degree-three
/// gate times a degree-three pair after polynomial address selection) reach six.
pub const SHA_WORD_CAPACITY_CONSTRAINT_DEGREE_V1: u8 = 6;
/// Emitted STARK-local rows reserved by one SHA-256 compression block.
///
/// This is deliberately smaller than `sha256_word_air::WORD_AIR_ROWS_PER_BLOCK_V1`: the latter's
/// conceptual circuit count includes a standalone definition for every operation output, while this
/// STARK trace range-binds that output inside the operation row and therefore must not count the
/// same 664 definitions twice.
pub const SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1: usize = 1_064;
/// Per-call local initialization rows preceding the first compression block.
const SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1: usize = 8;
/// Per-call local digest-read rows following the last compression block.
pub const SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1: usize = 8;
/// Word-memory rows reserved by one SHA-256 compression block.
pub const SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1: usize = 2_136;
/// Per-call word-memory rows independent of block count.
pub const SHA_WORD_CAPACITY_MEMORY_ROWS_PER_CALL_V1: usize = 16;
/// New word identifiers allocated by each SHA-256 compression block.
pub const SHA_WORD_CAPACITY_WORD_IDS_PER_BLOCK_V1: usize = 680;
pub const SHA_WORD_CAPACITY_ROW_ACTIVE_V1: usize = SHA_WORD_BASE_WIDTH_V1;
pub const SHA_WORD_CAPACITY_FINAL_BLOCK_V1: usize = SHA_WORD_CAPACITY_ROW_ACTIVE_V1 + 1;
pub const SHA_WORD_CAPACITY_SORTED_SAME_NEXT_V1: usize = SHA_WORD_CAPACITY_FINAL_BLOCK_V1 + 1;
pub const SHA_WORD_CAPACITY_MESSAGE_MASK_V1: usize = SHA_WORD_CAPACITY_SORTED_SAME_NEXT_V1 + 1;
pub const SHA_WORD_CAPACITY_MARKER_MASK_V1: usize = SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + 4;
pub const SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1: usize = SHA_WORD_CAPACITY_MARKER_MASK_V1 + 4;
pub const SHA_WORD_CAPACITY_MESSAGE_COUNT_V1: usize = SHA_WORD_AUX_WIDTH_V1;
pub const SHA_WORD_CAPACITY_PADDING_PHASE_V1: usize = SHA_WORD_CAPACITY_MESSAGE_COUNT_V1 + 1;
pub const SHA_WORD_CAPACITY_ACTIVE_BLOCKS_V1: usize = SHA_WORD_CAPACITY_PADDING_PHASE_V1 + 1;
pub const SHA_WORD_CAPACITY_BLOCK_FIRST_V1: usize = SHA_WORD_STARK_FIXED_WIDTH_V1;
pub const SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1: usize = SHA_WORD_CAPACITY_BLOCK_FIRST_V1 + 1;
pub const SHA_WORD_CAPACITY_BLOCK_LAST_V1: usize = SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1 + 1;
pub const SHA_WORD_CAPACITY_MAX_BLOCK_LAST_V1: usize = SHA_WORD_CAPACITY_BLOCK_LAST_V1 + 1;
pub const SHA_WORD_CAPACITY_INPUT_WORD_V1: usize = SHA_WORD_CAPACITY_MAX_BLOCK_LAST_V1 + 1;
pub const SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1: usize = SHA_WORD_CAPACITY_INPUT_WORD_V1 + 1;
pub const SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1: usize = SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1 + 1;
pub const SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1: usize = SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1 + 1;
pub const SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1: usize = SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1 + 1;
pub const SHA_WORD_CAPACITY_CALL_FIRST_V1: usize = SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1 + 1;
pub const SHA_WORD_CAPACITY_CALL_LAST_V1: usize = SHA_WORD_CAPACITY_CALL_FIRST_V1 + 1;
pub const SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1: usize = SHA_WORD_CAPACITY_CALL_LAST_V1 + 1;
pub const SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1: usize =
    SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1 + 1;
pub const SHA_WORD_CAPACITY_EXACT_LENGTH_V1: usize = SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1 + 4;
const LOCAL_PRODUCT_BEFORE: usize = 0;
const LOCAL_PAIR_01: usize = LOCAL_PRODUCT_BEFORE + SHA_WORD_COPY_LANES_V1;
const LOCAL_PAIR_23: usize = LOCAL_PAIR_01 + SHA_WORD_COPY_LANES_V1;
const LOCAL_PAIR_45: usize = LOCAL_PAIR_23 + SHA_WORD_COPY_LANES_V1;
const LOCAL_QUAD: usize = LOCAL_PAIR_45 + SHA_WORD_COPY_LANES_V1;
const LOCAL_PRODUCT_AFTER: usize = LOCAL_QUAD + SHA_WORD_COPY_LANES_V1;
const MEMORY_EXEC_BEFORE: usize = 0;
const MEMORY_SORT_BEFORE: usize = MEMORY_EXEC_BEFORE + SHA_WORD_COPY_LANES_V1;
const MEMORY_EXEC_AFTER: usize = MEMORY_SORT_BEFORE + SHA_WORD_COPY_LANES_V1;
const MEMORY_SORT_AFTER: usize = MEMORY_EXEC_AFTER + SHA_WORD_COPY_LANES_V1;
const CONTINUATION_OFFSET: usize = SHA_WORD_LOCAL_PRODUCT_WIDTH_V1;
const CONT_SEGMENT_INDEX: usize = CONTINUATION_OFFSET;
const CONT_GLOBAL_START: usize = CONT_SEGMENT_INDEX + 1;
const CONT_GLOBAL_END: usize = CONT_GLOBAL_START + 1;
const CONT_LOCAL_START: usize = CONT_GLOBAL_END + 1;
const CONT_LOCAL_END: usize = CONT_LOCAL_START + 1;
const CONT_MEMORY_START: usize = CONT_LOCAL_END + 1;
const CONT_MEMORY_END: usize = CONT_MEMORY_START + 1;
const CONT_EXEC_START: usize = CONT_MEMORY_END + 1;
const CONT_EXEC_END: usize = CONT_EXEC_START + SHA_WORD_COPY_LANES_V1;
const CONT_SORT_START: usize = CONT_EXEC_END + SHA_WORD_COPY_LANES_V1;
const CONT_SORT_END: usize = CONT_SORT_START + SHA_WORD_COPY_LANES_V1;
const GLOBAL_LOCAL_PRODUCT_END: usize = CONT_SORT_END + SHA_WORD_COPY_LANES_V1;
const _: () = {
    assert!(SHA_WORD_COPY_LANES_V1 == 4);
    assert!(SHA_WORD_LOCAL_PRODUCT_WIDTH_V1 == 24);
    assert!(SHA_WORD_MEMORY_PRODUCT_WIDTH_V1 == 16);
    assert!(SHA_WORD_CONTINUATION_WIDTH_V1 == 23);
    assert!(SHA_WORD_AUX_WIDTH_V1 == 51);
    assert!(GLOBAL_LOCAL_PRODUCT_END + SHA_WORD_COPY_LANES_V1 == SHA_WORD_AUX_WIDTH_V1);
    assert!(SHA_WORD_STARK_CONSTRAINT_COUNT_V1 == 155);
    assert!(SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1 + 1 == SHA_WORD_CAPACITY_BASE_WIDTH_V1);
    assert!(SHA_WORD_CAPACITY_ACTIVE_BLOCKS_V1 + 1 == SHA_WORD_CAPACITY_AUX_WIDTH_V1);
    assert!(SHA_WORD_CAPACITY_EXACT_LENGTH_V1 + 1 == SHA_WORD_CAPACITY_FIXED_WIDTH_V1);
    assert!(SHA_WORD_CAPACITY_CONTROL_CONSTRAINT_COUNT_V1 == 180);
    assert!(SHA_WORD_CAPACITY_CONSTRAINT_COUNT_V1 == 335);
};
const FIX_WORD: usize = 0;
const FIX_SIGMA_SMALL_ZERO: usize = 1;
const FIX_SIGMA_SMALL_ONE: usize = 2;
const FIX_SIGMA_BIG_ZERO: usize = 3;
const FIX_SIGMA_BIG_ONE: usize = 4;
const FIX_CHOOSE: usize = 5;
const FIX_MAJORITY: usize = 6;
const FIX_ADD_ARITY_TWO: usize = 7;
const FIX_ADD_ARITY_FOUR: usize = 8;
const FIX_DIGEST: usize = 9;
const FIX_MEMORY: usize = 10;
const FIX_PADDING: usize = 11;
const FIX_LOCAL_FIRST: usize = 12;
const FIX_LOCAL_CONTINUE: usize = 13;
const FIX_LOCAL_LAST: usize = 14;
const FIX_MEMORY_CONTINUE: usize = 15;
const FIX_MEMORY_SAME_NEXT: usize = 16;
const FIX_MEMORY_NEW_NEXT: usize = 17;
const FIX_MEMORY_FIRST_SEGMENT: usize = 18;
const FIX_MEMORY_LAST_SEGMENT: usize = 19;
const FIX_FIRST_AGGREGATE_ROW: usize = 20;
const FIX_LAST_AGGREGATE_ROW: usize = 21;
const FIX_PHYSICAL_BOUNDARY: usize = 22;
const FIX_CONTINUATION_WITHIN_SLOT: usize = 23;
const FIX_BOOLEAN_FIRST: usize = 24;
const FIX_BOOLEAN_CONTINUE: usize = 25;
const FIX_BOOLEAN_LAST: usize = 26;
const FIX_BOOLEAN_SCALE: usize = 27;
const FIX_BOOLEAN_NEXT_SCALE: usize = 28;
const FIX_WORD_BYTE_MASK: usize = 29;
const FIX_WORD_BYTE_EXPECTED: usize = 33;
const FIX_ADD_CONSTANT: usize = 37;
const FIX_DIGEST_EXPECTED: usize = 38;
const FIX_EVENT_ADDRESS: usize = 39;
const FIX_MEMORY_EXECUTION_ADDRESS: usize = 44;
const FIX_MEMORY_EXECUTION_WRITE: usize = 45;
const FIX_MEMORY_SORTED_ADDRESS: usize = 46;
const FIX_MEMORY_SORTED_WRITE: usize = 47;
const FIX_CONTINUATION_PUBLIC: usize = 48;
/// Raw fixed selector used by the capacity/call wrapper for digest rows.
pub const SHA_WORD_CAPACITY_DIGEST_SELECTOR_V1: usize = FIX_DIGEST;
/// Final row-kind selector in the capacity wrapper's exhaustive public schedule.
#[cfg(test)]
pub const SHA_WORD_CAPACITY_MEMORY_SELECTOR_V1: usize = FIX_MEMORY;
/// Fixed columns omitted from the zk-X509 preprocessed SHA oracle.
///
/// These six columns carry no independent information under the canonical 29-call schedule. Three
/// are identically zero and the remaining three are exact linear combinations of retained columns.
/// Since LDE is linear, the same reconstruction identities hold at every verifier opening, not
/// merely on native trace rows.
#[cfg(test)]
pub const ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1: [usize; 6] = [
    FIX_PADDING,
    FIX_LOCAL_CONTINUE,
    FIX_MEMORY_CONTINUE,
    FIX_LAST_AGGREGATE_ROW,
    FIX_PHYSICAL_BOUNDARY,
    FIX_BOOLEAN_CONTINUE,
];
/// Independent SHA-word fixed columns retained by the zk-X509 oracle.
#[cfg(test)]
pub const ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1: usize =
    SHA_WORD_CAPACITY_FIXED_WIDTH_V1 - ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1.len();
/// Public statement needed to compile the fixed SHA schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ShaWordStarkStatementV1 {
    /// Exact unpadded byte length; message bytes remain private.
    pub(crate) message_len: usize,
    /// Verifier-fixed SHA-256 digest.
    pub(crate) digest: [u8; 32],
}
/// SHA word trace construction or algebraic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkX509ShaWordStarkErrorV1 {
    /// Message length, schedule, or physical segmentation is invalid.
    #[error("zk-X509 SHA word STARK topology is invalid")]
    Topology,
    /// A local word/range/bitwise/addition constraint is unsatisfied.
    #[error("zk-X509 SHA word STARK local constraint is invalid")]
    LocalConstraint,
    /// The local references do not equal the global memory execution tuples.
    #[error("zk-X509 SHA word STARK local copy product is invalid")]
    LocalCopy,
    /// Execution/sorted memory or its products are invalid.
    #[cfg(test)]
    #[error("zk-X509 SHA word STARK memory constraint is invalid")]
    Memory,
    /// A physical continuation is malformed.
    #[cfg(test)]
    #[error("zk-X509 SHA word STARK continuation is invalid")]
    Continuation,
    /// Bounded row/allocation arithmetic failed.
    #[error("zk-X509 SHA word STARK resource bound is exceeded")]
    Resource,
}
impl From<ZkX509Sha256WordAirErrorV1> for ZkX509ShaWordStarkErrorV1 {
    fn from(_: ZkX509Sha256WordAirErrorV1) -> Self {
        Self::Topology
    }
}
#[cfg(test)]
fn reconstructed_zk_x509_sha_word_fixed_columns_v1(
    retained: &[F; ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1],
) -> [F; ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1.len()] {
    let mut expanded = [F::ZERO; SHA_WORD_CAPACITY_FIXED_WIDTH_V1];
    let mut retained_index = 0;
    for (column, target) in expanded.iter_mut().enumerate() {
        if ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1.contains(&column) {
            continue;
        }
        *target = retained[retained_index];
        retained_index += 1;
    }
    debug_assert_eq!(retained_index, ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1);
    let local_operation = expanded[FIX_WORD..=FIX_DIGEST]
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    [
        F::ZERO,
        // Every local row, including the mandatory first initialization row,
        // owns exactly one operation. Only the final local row does not
        // continue.
        local_operation.sub(expanded[FIX_LOCAL_LAST]),
        expanded[FIX_MEMORY_SAME_NEXT].add(expanded[FIX_MEMORY_NEW_NEXT]),
        F::ZERO,
        F::ZERO,
        expanded[FIX_CHOOSE]
            .add(expanded[FIX_MAJORITY])
            .sub(expanded[FIX_BOOLEAN_LAST]),
    ]
}
/// Remove the six algebraically redundant zk-X509 SHA fixed columns.
///
/// Native preprocessing calls this before committing a row, so a future
/// schedule change that violates any reconstruction identity fails closed
/// instead of silently changing the fixed-oracle language.
#[cfg(test)]
pub fn reduce_zk_x509_sha_word_fixed_row_v1(
    full: &[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1],
) -> Result<[F; ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
    let mut retained = [F::ZERO; ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1];
    let mut retained_index = 0;
    for (column, value) in full.iter().copied().enumerate() {
        if ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1.contains(&column) {
            continue;
        }
        retained[retained_index] = value;
        retained_index += 1;
    }
    if retained_index != ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let reconstructed = reconstructed_zk_x509_sha_word_fixed_columns_v1(&retained);
    if ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1
        .into_iter()
        .zip(reconstructed)
        .any(|(column, expected)| full[column] != expected)
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    Ok(retained)
}
/// Reconstruct all SHA-word fixed columns from one authenticated reduced LDE opening.
#[cfg(test)]
pub fn expand_zk_x509_sha_word_fixed_row_v1(
    retained: &[F; ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1],
) -> [F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1] {
    let mut expanded = [F::ZERO; SHA_WORD_CAPACITY_FIXED_WIDTH_V1];
    let mut retained_index = 0;
    for (column, target) in expanded.iter_mut().enumerate() {
        if ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1.contains(&column) {
            continue;
        }
        *target = retained[retained_index];
        retained_index += 1;
    }
    debug_assert_eq!(retained_index, ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1);
    for (column, value) in ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1
        .into_iter()
        .zip(reconstructed_zk_x509_sha_word_fixed_columns_v1(retained))
    {
        expanded[column] = value;
    }
    expanded
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShaWordFixedRowV1 {
    Word {
        address: usize,
        fixed_bits: [i8; 32],
    },
    Sigma {
        input: usize,
        output: usize,
        rotate_first: u8,
        rotate_second: u8,
        third: SigmaThirdV1,
    },
    Choose {
        addresses: [usize; 4],
        chunk: u8,
    },
    Majority {
        addresses: [usize; 4],
        chunk: u8,
    },
    Add {
        inputs: [usize; 5],
        arity: u8,
        constant: u32,
        output: usize,
    },
    Digest {
        address: usize,
        expected: u32,
    },
    Memory {
        execution_address: usize,
        execution_write: bool,
        sorted_address: usize,
        sorted_write: bool,
        sorted_same_address_next: bool,
        memory_first: bool,
        memory_last: bool,
    },
    #[cfg(test)]
    Padding,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShaWordPhysicalContinuationV1 {
    pub(crate) segment_index: u8,
    pub(crate) global_row_start: usize,
    pub(crate) global_row_end: usize,
    pub(crate) local_row_start: usize,
    pub(crate) local_row_end: usize,
    pub(crate) memory_row_start: usize,
    pub(crate) memory_row_end: usize,
    pub(crate) execution_product_start: [F; SHA_WORD_COPY_LANES_V1],
    pub(crate) execution_product_end: [F; SHA_WORD_COPY_LANES_V1],
    pub(crate) sorted_product_start: [F; SHA_WORD_COPY_LANES_V1],
    pub(crate) sorted_product_end: [F; SHA_WORD_COPY_LANES_V1],
}
#[derive(Clone)]
pub struct ZkX509ShaWordStarkBaseV1 {
    #[cfg(test)]
    pub(crate) statement: ZkX509ShaWordStarkStatementV1,
    pub(crate) base_rows: Vec<Vec<F>>,
    pub(crate) fixed_rows: Vec<ShaWordFixedRowV1>,
    pub(crate) local_events: Vec<Vec<WordMemoryAccessV1>>,
    pub(crate) execution: Vec<WordMemoryAccessV1>,
    pub(crate) sorted: Vec<WordMemoryAccessV1>,
    pub(crate) local_rows: usize,
    #[cfg(test)]
    pub(crate) segment_rows: usize,
    #[cfg(test)]
    pub(crate) active_rows_per_segment: Vec<usize>,
}
impl core::fmt::Debug for ZkX509ShaWordStarkBaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509ShaWordStarkBaseV1 { <private material redacted> }")
    }
}
fn zeroize_sha_word_events_v1(events: &mut [WordMemoryAccessV1]) {
    for event in events {
        event.address.zeroize_v1();
        event.value.zeroize_v1();
        event.is_write.zeroize_v1();
    }
}
fn zeroize_sha_word_event_rows_v1(rows: &mut [Vec<WordMemoryAccessV1>]) {
    for events in rows {
        zeroize_sha_word_events_v1(events);
    }
}
fn zeroize_sha_word_private_fixed_v1(rows: &mut [ShaWordFixedRowV1]) {
    for fixed in rows {
        if let ShaWordFixedRowV1::Digest { expected, .. } = fixed {
            zeroize::Zeroize::zeroize(expected);
        }
    }
}
impl ZkX509ShaWordStarkBaseV1 {
    fn zeroize_private_cells_v1(&mut self) {
        for value in self.base_rows.iter_mut().flatten() {
            value.zeroize_v1();
        }
        for events in &mut self.local_events {
            zeroize_sha_word_events_v1(events);
        }
        zeroize_sha_word_events_v1(&mut self.execution);
        zeroize_sha_word_events_v1(&mut self.sorted);
        // Raw digest rows bind the actual message digest. The verifier-owned
        // fixed schedule is moved out before this clearing owner is dropped.
        for fixed in &mut self.fixed_rows {
            if let ShaWordFixedRowV1::Digest { expected, .. } = fixed {
                zeroize::Zeroize::zeroize(expected);
            }
        }
        zeroize::Zeroize::zeroize(&mut self.local_rows);
        #[cfg(test)]
        {
            zeroize::Zeroize::zeroize(&mut self.statement.message_len);
            zeroize::Zeroize::zeroize(&mut self.statement.digest);
        }
    }
}
impl Drop for ZkX509ShaWordStarkBaseV1 {
    fn drop(&mut self) {
        self.zeroize_private_cells_v1();
    }
}
/// Challenge-independent fixed-capacity SHA word material.
///
/// This source owns every base and fixed row plus the private word-memory events needed to derive
/// auxiliary products later. No challenge-dependent row exists until [`Self::bind_v1`] consumes
/// this source with the opaque credential pre-auxiliary token.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct ZkX509ShaWordCapacityBaseSourceV1 {
    message_len: usize,
    #[cfg(test)]
    maximum_message_len: usize,
    #[cfg(test)]
    exact_length: bool,
    active_blocks: usize,
    maximum_blocks: usize,
    maximum_local_rows: usize,
    maximum_memory_rows: usize,
    actual_compute_rows: usize,
    maximum_compute_rows: usize,
    base_rows: Vec<[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1]>,
    fixed_rows: Vec<[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1]>,
    local_events: Vec<Vec<WordMemoryAccessV1>>,
    execution: Vec<WordMemoryAccessV1>,
    sorted: Vec<WordMemoryAccessV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509ShaWordCapacityBaseSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkX509ShaWordCapacityBaseSourceV1")
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ShaWordCapacityBaseSourceV1 {
    /// Exact private message length committed by the base rows.
    pub(crate) const fn message_len(&self) -> usize {
        self.message_len
    }
    /// Maximum compression blocks reserved by the fixed schedule.
    pub(crate) const fn maximum_blocks(&self) -> usize {
        self.maximum_blocks
    }
    /// Maximum local word-AIR rows.
    pub(crate) const fn maximum_local_rows(&self) -> usize {
        self.maximum_local_rows
    }
    /// Maximum word-memory rows.
    pub(crate) const fn maximum_memory_rows(&self) -> usize {
        self.maximum_memory_rows
    }
    /// Exact logical row count of this fixed-capacity call.
    pub(crate) const fn logical_rows(&self) -> usize {
        self.maximum_local_rows + self.maximum_memory_rows
    }
    /// Return one already-materialized challenge-independent base row.
    pub(crate) fn base_row(
        &self,
        index: usize,
    ) -> Result<&[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        self.base_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
    }
    /// Return one verifier-fixed row compiled before challenge sampling.
    pub(crate) fn fixed_row(
        &self,
        index: usize,
    ) -> Result<&[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        self.fixed_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
    }
    /// Consume the base phase and derive auxiliary rows from the opaque X5B1 credential token.
    pub(crate) fn bind_v1(
        self,
        binding: ZkX509CredentialPreAuxBindingV1,
    ) -> Result<ZkX509ShaWordCapacityTraceV1, ZkX509ShaWordStarkErrorV1> {
        self.bind_challenges_v1(binding.sha_word())
    }
    #[cfg(test)]
    pub(crate) fn bind_challenges_for_test_v1(
        self,
        challenges: ZkX509ShaWordStarkChallengesV1,
    ) -> Result<ZkX509ShaWordCapacityTraceV1, ZkX509ShaWordStarkErrorV1> {
        self.bind_challenges_v1(challenges)
    }
    fn zeroize_private_cells_v1(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.message_len);
        zeroize::Zeroize::zeroize(&mut self.active_blocks);
        zeroize::Zeroize::zeroize(&mut self.actual_compute_rows);
        for value in self.base_rows.iter_mut().flatten() {
            value.zeroize_v1();
        }
        for events in &mut self.local_events {
            zeroize_sha_word_events_v1(events);
        }
        zeroize_sha_word_events_v1(&mut self.execution);
        zeroize_sha_word_events_v1(&mut self.sorted);
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.zeroize_private_cells_v1();
        self.base_rows.clear();
        self.fixed_rows.clear();
        self.local_events.clear();
        self.execution.clear();
        self.sorted.clear();
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.message_len == 0
            && self.active_blocks == 0
            && self.actual_compute_rows == 0
            && self.base_rows.is_empty()
            && self.fixed_rows.is_empty()
            && self.local_events.is_empty()
            && self.execution.is_empty()
            && self.sorted.is_empty()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ShaWordCapacityBaseSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct ZkX509ShaWordStarkTraceV1 {
    pub(crate) base: ZkX509ShaWordStarkBaseV1,
    pub(crate) aux_rows: Vec<Vec<F>>,
    pub(crate) continuations: Vec<ShaWordPhysicalContinuationV1>,
}
/// One verifier-fixed maximum-capacity SHA call.
///
/// Only a single call is materialized at a time. The 29-call adapter streams these call traces into
/// its four physical segments and drops each call before constructing the next one.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone)]
pub struct ZkX509ShaWordCapacityTraceV1 {
    pub(crate) message_len: usize,
    #[cfg(test)]
    pub(crate) maximum_message_len: usize,
    #[cfg(test)]
    pub(crate) exact_length: bool,
    pub(crate) active_blocks: usize,
    #[cfg(test)]
    pub(crate) maximum_blocks: usize,
    pub(crate) maximum_local_rows: usize,
    pub(crate) maximum_memory_rows: usize,
    pub(crate) base_rows: Vec<[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1]>,
    pub(crate) aux_rows: Vec<[F; SHA_WORD_CAPACITY_AUX_WIDTH_V1]>,
    pub(crate) fixed_rows: Vec<[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509ShaWordCapacityTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkX509ShaWordCapacityTraceV1")
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ShaWordCapacityTraceV1 {
    fn zeroize_private_cells_v1(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.message_len);
        zeroize::Zeroize::zeroize(&mut self.active_blocks);
        for value in self.base_rows.iter_mut().flatten() {
            value.zeroize_v1();
        }
        for value in self.aux_rows.iter_mut().flatten() {
            value.zeroize_v1();
        }
    }
    /// Recursively overwrite message-derived rows and private geometry.
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.zeroize_private_cells_v1();
        self.base_rows.clear();
        self.aux_rows.clear();
        self.fixed_rows.clear();
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.message_len == 0
            && self.active_blocks == 0
            && self.base_rows.is_empty()
            && self.aux_rows.is_empty()
            && self.fixed_rows.is_empty()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ShaWordCapacityTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Verifier-owned fixed topology for one maximum-capacity SHA call.
///
/// Unlike [`ZkX509ShaWordCapacityTraceV1`], this value contains no exact message length, message
/// byte, active-block selector, digest value, or Fiat--Shamir product. It is therefore safe for an
/// independent verifier to compile solely from the public call manifest and replay at arbitrary
/// opened rows.
#[derive(Clone, Debug)]
pub struct ZkX509ShaWordCapacityFixedScheduleV1 {
    maximum_message_len: usize,
    exact_length: bool,
    maximum_blocks: usize,
    maximum_local_rows: usize,
    maximum_memory_rows: usize,
    maximum_compute_rows: usize,
    word: ZkX509ShaWordStarkFixedScheduleV1,
    input_word_indices: Vec<(usize, usize)>,
}
impl ZkX509ShaWordCapacityFixedScheduleV1 {
    /// Exact allocated public preprocessing payload, including spare capacity.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            vector_v1(&self.word.fixed_rows),
            vector_v1(&self.input_word_indices),
        ])
    }
    #[cfg(test)]
    pub(crate) const fn maximum_message_len(&self) -> usize {
        self.maximum_message_len
    }
    #[cfg(test)]
    pub(crate) const fn exact_length(&self) -> bool {
        self.exact_length
    }
    pub(crate) const fn maximum_blocks(&self) -> usize {
        self.maximum_blocks
    }
    pub(crate) const fn maximum_local_rows(&self) -> usize {
        self.maximum_local_rows
    }
    pub(crate) const fn maximum_memory_rows(&self) -> usize {
        self.maximum_memory_rows
    }
    pub(crate) const fn logical_rows(&self) -> usize {
        self.maximum_local_rows + self.maximum_memory_rows
    }
    /// Reconstruct one exact capacity-wrapper fixed row.
    pub(crate) fn fixed_row_v1(
        &self,
        index: usize,
    ) -> Result<[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        if index >= self.logical_rows() {
            return Err(ZkX509ShaWordStarkErrorV1::Resource);
        }
        let maximum_message_len_field = F(u64::try_from(self.maximum_message_len)
            .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
        let mut fixed = [F::ZERO; SHA_WORD_CAPACITY_FIXED_WIDTH_V1];
        fixed[..SHA_WORD_STARK_FIXED_WIDTH_V1].copy_from_slice(&self.word.fixed_row_v1(index)?);
        fixed[SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1] = maximum_message_len_field;
        fixed[SHA_WORD_CAPACITY_EXACT_LENGTH_V1] = F(u64::from(self.exact_length));
        if index < self.maximum_local_rows {
            if index < SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1 {
                // The initial-state definition rows form a mandatory prefix.
                if index + 1 < SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1 {
                    fixed[SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1] = F::ONE;
                } else {
                    fixed[SHA_WORD_CAPACITY_BLOCK_LAST_V1] = F::ONE;
                }
            } else if index < self.maximum_compute_rows {
                let block_row = index
                    .checked_sub(SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1)
                    .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
                let within_block = block_row % SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1;
                fixed[SHA_WORD_CAPACITY_BLOCK_FIRST_V1] = F(u64::from(within_block == 0));
                fixed[SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1] = F(u64::from(
                    within_block + 1 < SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1,
                ));
                fixed[SHA_WORD_CAPACITY_BLOCK_LAST_V1] = F(u64::from(
                    within_block + 1 == SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1,
                ));
                fixed[SHA_WORD_CAPACITY_MAX_BLOCK_LAST_V1] =
                    F(u64::from(index + 1 == self.maximum_compute_rows));
            }
            match self.word.fixed_rows.get(index) {
                Some(ShaWordFixedRowV1::Word { address, .. }) => {
                    if let Ok(position) = self
                        .input_word_indices
                        .binary_search_by_key(address, |entry| entry.0)
                    {
                        let input_word = self.input_word_indices[position].1;
                        fixed[SHA_WORD_CAPACITY_INPUT_WORD_V1] = F::ONE;
                        fixed[SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1] = F(u64::try_from(input_word)
                            .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
                        fixed[SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1] =
                            F(u64::from(input_word % 16 == 14));
                        fixed[SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1] =
                            F(u64::from(input_word % 16 == 15));
                        for byte in 0..4 {
                            let byte_index = input_word
                                .checked_mul(4)
                                .and_then(|offset| offset.checked_add(byte))
                                .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
                            if byte_index < self.maximum_message_len {
                                fixed[SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1 + byte] = F::ONE;
                            }
                        }
                    }
                }
                Some(ShaWordFixedRowV1::Digest { .. }) => {
                    let digest_index = index
                        .checked_sub(self.maximum_compute_rows)
                        .filter(|digest| *digest < SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1)
                        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
                    fixed[SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1] = F(u64::try_from(digest_index)
                        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
                }
                Some(_) => {}
                None => return Err(ZkX509ShaWordStarkErrorV1::Topology),
            }
            if index == 0 {
                fixed[SHA_WORD_CAPACITY_CALL_FIRST_V1] = F::ONE;
            }
        } else if index + 1 == self.logical_rows() {
            fixed[SHA_WORD_CAPACITY_CALL_LAST_V1] = F::ONE;
        }
        Ok(fixed)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ShaWordCapacityTraceV1 {
    pub(crate) const fn logical_rows(&self) -> usize {
        self.maximum_local_rows + self.maximum_memory_rows
    }
    pub(crate) fn base_row(
        &self,
        index: usize,
    ) -> Result<&[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        self.base_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
    }
    pub(crate) fn aux_row(
        &self,
        index: usize,
    ) -> Result<&[F; SHA_WORD_CAPACITY_AUX_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        self.aux_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
    }
    pub(crate) fn fixed_row(
        &self,
        index: usize,
    ) -> Result<&[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        self.fixed_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
    }
}
/// Compile the fixed portion of a maximum-capacity SHA call without any
/// private call witness or transcript challenge.
pub fn compile_sha_word_capacity_fixed_schedule_v1(
    maximum_message_len: usize,
    exact_length: bool,
) -> Result<ZkX509ShaWordCapacityFixedScheduleV1, ZkX509ShaWordStarkErrorV1> {
    if maximum_message_len > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    let maximum_blocks = capacity_blocks_v1(maximum_message_len)?;
    let maximum_local_rows = capacity_local_rows_v1(maximum_blocks)?;
    let maximum_memory_rows = capacity_memory_rows_v1(maximum_blocks)?;
    let maximum_logical_rows = maximum_local_rows
        .checked_add(maximum_memory_rows)
        .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
    if maximum_logical_rows > SHA_WORD_AGGREGATE_TRACE_SIZE_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    let maximum_compute_rows = maximum_local_rows
        .checked_sub(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
    if maximum_compute_rows
        != maximum_blocks * SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1
            + SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    // Only topology is retained. The all-zero shape message is public,
    // deterministic compiler input and is dropped before this function
    // returns.
    let maximum_message = vec![0_u8; maximum_message_len];
    let maximum_circuit = build_sha256_word_circuit_v1(&maximum_message)?;
    let maximum_statement = ZkX509ShaWordStarkStatementV1 {
        message_len: maximum_message_len,
        digest: maximum_circuit.digest(),
    };
    let mut maximum = build_sha_word_stark_base_v1(maximum_statement, &maximum_message)?;
    drop(maximum_message);
    if maximum.local_rows != maximum_local_rows
        || maximum.execution.len() != maximum_memory_rows
        || maximum.fixed_rows.len() != maximum_logical_rows
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let slots = aggregate_slots_v1(maximum.local_rows, maximum_logical_rows)?;
    let fixed_rows = core::mem::take(&mut maximum.fixed_rows);
    drop(maximum);
    let word = ZkX509ShaWordStarkFixedScheduleV1 {
        #[cfg(test)]
        statement: maximum_statement,
        fixed_rows,
        local_rows: maximum_local_rows,
        logical_rows: maximum_logical_rows,
        slots,
    };
    let mut input_word_indices = maximum_circuit
        .stark_input_words_v1()
        .iter()
        .copied()
        .enumerate()
        .map(|(index, word)| (word.0, index))
        .collect::<Vec<_>>();
    input_word_indices.sort_unstable_by_key(|entry| entry.0);
    drop(maximum_circuit);
    if input_word_indices.len() != maximum_blocks * 16
        || input_word_indices
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    Ok(ZkX509ShaWordCapacityFixedScheduleV1 {
        maximum_message_len,
        exact_length,
        maximum_blocks,
        maximum_local_rows,
        maximum_memory_rows,
        maximum_compute_rows,
        word,
        input_word_indices,
    })
}
/// Fiat-Shamir challenges consumed by the numeric aggregate adapter.
///
/// `memory` binds local references to the execution and address-sorted word memory. `base_folding`
/// is sampled only after the base commitment and folds the 441 base-only errors into four
/// independent residues. It is never used to fold auxiliary constraints because the auxiliary trace
/// is committed after these challenges are known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ShaWordStarkChallengesV1 {
    pub(crate) memory: ZkX509WordMemoryChallengesV1,
    pub(crate) base_folding: [F; SHA_WORD_COPY_LANES_V1],
}
/// Derive the four base-error-folding challenges after word-memory challenges.
pub fn derive_zk_x509_sha_word_base_folding_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<[F; SHA_WORD_COPY_LANES_V1], TransparentStarkErrorV1> {
    let mut base_folding = [F::ZERO; SHA_WORD_COPY_LANES_V1];
    for (lane, challenge) in base_folding.iter_mut().enumerate() {
        let lane = u16::try_from(lane)
            .expect("four SHA folding lanes fit u16")
            .to_be_bytes();
        let label = [b"zk-x509-sha-word-base-error-folding-v1".as_slice(), &lane].concat();
        *challenge = transcript.challenge_field(&label)?;
    }
    Ok(base_folding)
}
/// Derive the complete SHA-word challenge family after all SHA base
/// commitments have been transcript-bound.
#[cfg(test)]
pub fn derive_zk_x509_sha_word_stark_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509ShaWordStarkChallengesV1, TransparentStarkErrorV1> {
    let memory = derive_sha256_word_memory_challenges_v1(transcript)?;
    let base_folding = derive_zk_x509_sha_word_base_folding_challenges_v1(transcript)?;
    Ok(ZkX509ShaWordStarkChallengesV1 {
        memory,
        base_folding,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ShaWordAggregateSlotV1 {
    segment_index: u8,
    global_row_start: usize,
    global_row_end: usize,
    local_row_start: usize,
    local_row_end: usize,
    memory_row_start: usize,
    memory_row_end: usize,
}
/// Verifier-owned logical schedule embedded in the common aggregate domain.
///
/// Only logical fixed rows are retained. Padding rows and both physical-slot
/// continuation labels are reconstructed on demand, so merely compiling a
/// short statement does not allocate a million fixed rows.
#[derive(Clone, Debug)]
pub struct ZkX509ShaWordStarkFixedScheduleV1 {
    #[cfg(test)]
    statement: ZkX509ShaWordStarkStatementV1,
    fixed_rows: Vec<ShaWordFixedRowV1>,
    local_rows: usize,
    logical_rows: usize,
    slots: [ShaWordAggregateSlotV1; 2],
}
#[cfg(test)]
impl ZkX509ShaWordStarkFixedScheduleV1 {
    pub(crate) const fn logical_rows(&self) -> usize {
        self.logical_rows
    }
    pub(crate) const fn aggregate_rows(&self) -> usize {
        SHA_WORD_AGGREGATE_TRACE_SIZE_V1
    }
    pub(crate) const fn local_rows(&self) -> usize {
        self.local_rows
    }
    pub(crate) const fn memory_rows(&self) -> usize {
        self.logical_rows - self.local_rows
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compress_access(access: WordMemoryAccessV1, challenge: ZkX509WordMemoryLaneChallengesV1) -> F {
    challenge
        .beta
        .add(challenge.address.mul(access.address))
        .add(challenge.value.mul(access.value))
        .add(challenge.is_write.mul(access.is_write))
}
fn validate_challenges(
    challenges: ZkX509WordMemoryChallengesV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    for lane in challenges.lanes {
        let coefficients = [lane.beta, lane.address, lane.value, lane.is_write];
        if coefficients
            .iter()
            .any(|coefficient| F::canonical(coefficient.0).is_none() || *coefficient == F::ZERO)
        {
            return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
        }
    }
    if challenges
        .lanes
        .iter()
        .enumerate()
        .any(|(index, lane)| challenges.lanes[..index].contains(lane))
    {
        return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
    }
    Ok(())
}
/// Reject invalid word-memory or base-error-folding challenges.
pub fn validate_zk_x509_sha_word_stark_challenges_v1(
    challenges: ZkX509ShaWordStarkChallengesV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    validate_challenges(challenges.memory)?;
    if challenges.base_folding.iter().any(|challenge| {
        challenge.0 == 0
            || challenge.0 >= GOLDILOCKS_MODULUS_V1
            || F::canonical(challenge.0).is_none()
    }) || challenges
        .base_folding
        .iter()
        .enumerate()
        .any(|(index, challenge)| challenges.base_folding[..index].contains(challenge))
    {
        return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn local_product_row(
    events: &[WordMemoryAccessV1],
    before: [F; SHA_WORD_COPY_LANES_V1],
    challenges: ZkX509WordMemoryChallengesV1,
) -> Result<
    (
        [F; SHA_WORD_LOCAL_PRODUCT_WIDTH_V1],
        [F; SHA_WORD_COPY_LANES_V1],
    ),
    ZkX509ShaWordStarkErrorV1,
> {
    if events.len() > 6 {
        return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
    }
    let mut row = [F::ZERO; SHA_WORD_LOCAL_PRODUCT_WIDTH_V1];
    let mut after = before;
    row[LOCAL_PRODUCT_BEFORE..LOCAL_PRODUCT_BEFORE + SHA_WORD_COPY_LANES_V1]
        .copy_from_slice(&before);
    for lane in 0..SHA_WORD_COPY_LANES_V1 {
        let factors: [F; 6] = core::array::from_fn(|index| {
            events.get(index).copied().map_or(F::ONE, |access| {
                compress_access(access, challenges.lanes[lane])
            })
        });
        let pair01 = factors[0].mul(factors[1]);
        let pair23 = factors[2].mul(factors[3]);
        let pair45 = factors[4].mul(factors[5]);
        let quad = pair01.mul(pair23);
        after[lane] = before[lane].mul(quad).mul(pair45);
        row[LOCAL_PAIR_01 + lane] = pair01;
        row[LOCAL_PAIR_23 + lane] = pair23;
        row[LOCAL_PAIR_45 + lane] = pair45;
        row[LOCAL_QUAD + lane] = quad;
        row[LOCAL_PRODUCT_AFTER + lane] = after[lane];
    }
    Ok((row, after))
}
#[cfg(test)]
fn products_at(
    rows: &[[F; SHA_WORD_MEMORY_PRODUCT_WIDTH_V1]],
    offset: usize,
) -> Result<([F; SHA_WORD_COPY_LANES_V1], [F; SHA_WORD_COPY_LANES_V1]), ZkX509ShaWordStarkErrorV1> {
    if offset == 0 {
        return Ok((
            [F::ONE; SHA_WORD_COPY_LANES_V1],
            [F::ONE; SHA_WORD_COPY_LANES_V1],
        ));
    }
    let row = rows
        .get(offset - 1)
        .ok_or(ZkX509ShaWordStarkErrorV1::Continuation)?;
    Ok((
        row[MEMORY_EXEC_AFTER..MEMORY_EXEC_AFTER + SHA_WORD_COPY_LANES_V1]
            .try_into()
            .expect("four execution products"),
        row[MEMORY_SORT_AFTER..MEMORY_SORT_AFTER + SHA_WORD_COPY_LANES_V1]
            .try_into()
            .expect("four sorted products"),
    ))
}
#[cfg(test)]
fn build_continuations(
    base: &ZkX509ShaWordStarkBaseV1,
    memory_products: &[[F; SHA_WORD_MEMORY_PRODUCT_WIDTH_V1]],
) -> Result<Vec<ShaWordPhysicalContinuationV1>, ZkX509ShaWordStarkErrorV1> {
    let total_rows = base.base_rows.len();
    let mut continuations = Vec::with_capacity(base.active_rows_per_segment.len());
    for (segment, active_rows) in base.active_rows_per_segment.iter().copied().enumerate() {
        let global_row_start = segment
            .checked_mul(base.segment_rows)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
        let global_row_end = global_row_start
            .checked_add(active_rows)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?
            .min(total_rows);
        let local_row_start = global_row_start.min(base.local_rows);
        let local_row_end = global_row_end.min(base.local_rows);
        let memory_row_start = global_row_start
            .saturating_sub(base.local_rows)
            .min(base.execution.len());
        let memory_row_end = global_row_end
            .saturating_sub(base.local_rows)
            .min(base.execution.len());
        let (execution_product_start, sorted_product_start) =
            products_at(memory_products, memory_row_start)?;
        let (execution_product_end, sorted_product_end) =
            products_at(memory_products, memory_row_end)?;
        continuations.push(ShaWordPhysicalContinuationV1 {
            segment_index: u8::try_from(segment)
                .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?,
            global_row_start,
            global_row_end,
            local_row_start,
            local_row_end,
            memory_row_start,
            memory_row_end,
            execution_product_start,
            execution_product_end,
            sorted_product_start,
            sorted_product_end,
        });
    }
    Ok(continuations)
}
#[cfg(test)]
fn write_continuation(
    row: &mut [F],
    continuation: ShaWordPhysicalContinuationV1,
    local_product_end: [F; SHA_WORD_COPY_LANES_V1],
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    let as_field = |value: usize| {
        u64::try_from(value)
            .map(F)
            .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)
    };
    row[CONT_SEGMENT_INDEX] = F(u64::from(continuation.segment_index));
    row[CONT_GLOBAL_START] = as_field(continuation.global_row_start)?;
    row[CONT_GLOBAL_END] = as_field(continuation.global_row_end)?;
    row[CONT_LOCAL_START] = as_field(continuation.local_row_start)?;
    row[CONT_LOCAL_END] = as_field(continuation.local_row_end)?;
    row[CONT_MEMORY_START] = as_field(continuation.memory_row_start)?;
    row[CONT_MEMORY_END] = as_field(continuation.memory_row_end)?;
    row[CONT_EXEC_START..CONT_EXEC_START + SHA_WORD_COPY_LANES_V1]
        .copy_from_slice(&continuation.execution_product_start);
    row[CONT_EXEC_END..CONT_EXEC_END + SHA_WORD_COPY_LANES_V1]
        .copy_from_slice(&continuation.execution_product_end);
    row[CONT_SORT_START..CONT_SORT_START + SHA_WORD_COPY_LANES_V1]
        .copy_from_slice(&continuation.sorted_product_start);
    row[CONT_SORT_END..CONT_SORT_END + SHA_WORD_COPY_LANES_V1]
        .copy_from_slice(&continuation.sorted_product_end);
    row[GLOBAL_LOCAL_PRODUCT_END..GLOBAL_LOCAL_PRODUCT_END + SHA_WORD_COPY_LANES_V1]
        .copy_from_slice(&local_product_end);
    Ok(())
}
/// Attach challenge-dependent local-reference, memory-copy, and continuation auxiliary columns.
#[cfg(test)]
pub fn build_sha_word_stark_trace_v1(
    base: ZkX509ShaWordStarkBaseV1,
    challenges: ZkX509WordMemoryChallengesV1,
) -> Result<ZkX509ShaWordStarkTraceV1, ZkX509ShaWordStarkErrorV1> {
    validate_challenges(challenges)?;
    let mut local_aux = Vec::with_capacity(base.local_rows);
    let mut local_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
    for events in &base.local_events {
        let (row, after) = local_product_row(events, local_product, challenges)?;
        local_aux.push(row);
        local_product = after;
    }
    let mut memory_products = Vec::with_capacity(base.execution.len());
    let mut execution_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
    let mut sorted_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
    for (execution, sorted) in base
        .execution
        .iter()
        .copied()
        .zip(base.sorted.iter().copied())
    {
        let mut row = [F::ZERO; SHA_WORD_MEMORY_PRODUCT_WIDTH_V1];
        row[MEMORY_EXEC_BEFORE..MEMORY_EXEC_BEFORE + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&execution_product);
        row[MEMORY_SORT_BEFORE..MEMORY_SORT_BEFORE + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&sorted_product);
        for lane in 0..SHA_WORD_COPY_LANES_V1 {
            execution_product[lane] =
                execution_product[lane].mul(compress_access(execution, challenges.lanes[lane]));
            sorted_product[lane] =
                sorted_product[lane].mul(compress_access(sorted, challenges.lanes[lane]));
        }
        row[MEMORY_EXEC_AFTER..MEMORY_EXEC_AFTER + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&execution_product);
        row[MEMORY_SORT_AFTER..MEMORY_SORT_AFTER + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&sorted_product);
        memory_products.push(row);
    }
    if execution_product != sorted_product || local_product != execution_product {
        return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
    }
    let continuations = build_continuations(&base, &memory_products)?;
    let mut aux_rows = Vec::with_capacity(base.base_rows.len());
    for global_row in 0..base.base_rows.len() {
        let mut row = vec![F::ZERO; SHA_WORD_AUX_WIDTH_V1];
        if global_row < base.local_rows {
            row[..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1].copy_from_slice(&local_aux[global_row]);
        } else {
            let memory_row = global_row - base.local_rows;
            row[..SHA_WORD_MEMORY_PRODUCT_WIDTH_V1].copy_from_slice(&memory_products[memory_row]);
        }
        let segment = (global_row / base.segment_rows).min(continuations.len() - 1);
        write_continuation(&mut row, continuations[segment], local_product)?;
        aux_rows.push(row);
    }
    let trace = ZkX509ShaWordStarkTraceV1 {
        base,
        aux_rows,
        continuations,
    };
    validate_sha_word_stark_trace_v1(&trace, challenges)?;
    Ok(trace)
}
fn capacity_blocks_v1(message_len: usize) -> Result<usize, ZkX509ShaWordStarkErrorV1> {
    message_len
        .checked_add(9)
        .and_then(|length| length.checked_add(63))
        .map(|length| length / 64)
        .filter(|blocks| *blocks != 0)
        .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
}
fn capacity_local_rows_v1(blocks: usize) -> Result<usize, ZkX509ShaWordStarkErrorV1> {
    blocks
        .checked_mul(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1)
        .and_then(|rows| rows.checked_add(SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1))
        .and_then(|rows| rows.checked_add(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
}
fn capacity_memory_rows_v1(blocks: usize) -> Result<usize, ZkX509ShaWordStarkErrorV1> {
    blocks
        .checked_mul(SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1)
        .and_then(|rows| rows.checked_add(SHA_WORD_CAPACITY_MEMORY_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn capacity_raw_base_row_v1(
    row: &[F],
) -> Result<[F; SHA_WORD_BASE_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
    row.try_into()
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Topology)
}
/// Conservative payload forecast for constructing and replaying one SHA call.
///
/// Counts six simultaneous circuit copies, raw rows/events, complete capacity
/// matrices and call products, plus bounded sorting/index scratch. This intentionally
/// overcharges owners whose scopes do not overlap. Allocator metadata is excluded.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn source_replay_scratch_forecast_v1(
    maximum_blocks: usize,
) -> Result<usize, ZkX509ShaWordStarkErrorV1> {
    use super::air::U32RangeAirRowV1;
    use core::mem::size_of;
    if maximum_blocks == 0
        || maximum_blocks > capacity_blocks_v1(ZK_X509_DER_MAX_DOCUMENT_BYTES_V1)?
    {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    let local = capacity_local_rows_v1(maximum_blocks)?;
    let memory = capacity_memory_rows_v1(maximum_blocks)?;
    let rows = local
        .checked_add(memory)
        .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
    let circuit = local.next_power_of_two()
        * (size_of::<U32RangeAirRowV1>() + size_of::<WordOperationV1>())
        + (maximum_blocks * 16).next_power_of_two() * size_of::<WordIdV1>()
        + 2 * memory.next_power_of_two() * size_of::<WordMemoryAccessV1>();
    let event_heap = 6 * local * size_of::<WordMemoryAccessV1>();
    let memory_tables = 2 * memory.next_power_of_two() * size_of::<WordMemoryAccessV1>();
    let raw = rows * SHA_WORD_BASE_WIDTH_V1 * size_of::<F>()
        + rows * (2 * size_of::<Vec<F>>() + size_of::<ShaWordFixedRowV1>())
        + event_heap
        + memory_tables;
    let bound = rows
        * (SHA_WORD_CAPACITY_BASE_WIDTH_V1
            + SHA_WORD_CAPACITY_FIXED_WIDTH_V1
            + SHA_WORD_CAPACITY_AUX_WIDTH_V1
            + 24)
        * size_of::<F>()
        + rows * size_of::<Vec<WordMemoryAccessV1>>()
        + event_heap
        + memory_tables;
    Ok(6 * circuit + raw + bound + (32 << 20))
}

/// Build the challenge-independent phase of one fixed-capacity SHA call.
///
/// The verifier-visible shape depends only on `maximum_message_len`. The exact message length,
/// active-block prefix, padding transition, selected digest state, and memory activity remain
/// committed witness columns. Word memory products are intentionally absent until the returned
/// source binds an opaque X5B1 token.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_sha_word_capacity_base_source_v1(
    message: &[u8],
    maximum_message_len: usize,
    exact_length: bool,
) -> Result<ZkX509ShaWordCapacityBaseSourceV1, ZkX509ShaWordStarkErrorV1> {
    if message.len() > maximum_message_len
        || maximum_message_len > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1
    {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    if exact_length && message.len() != maximum_message_len {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let active_blocks = capacity_blocks_v1(message.len())?;
    let fixed_schedule =
        compile_sha_word_capacity_fixed_schedule_v1(maximum_message_len, exact_length)?;
    let maximum_blocks = fixed_schedule.maximum_blocks();
    let maximum_local_rows = fixed_schedule.maximum_local_rows();
    let maximum_memory_rows = fixed_schedule.maximum_memory_rows();
    let maximum_logical_rows = fixed_schedule.logical_rows();
    let actual_circuit = build_sha256_word_circuit_v1(message)?;
    let actual_statement = ZkX509ShaWordStarkStatementV1 {
        message_len: message.len(),
        digest: actual_circuit.digest(),
    };
    let mut actual = build_sha_word_stark_base_v1(actual_statement, message)?;
    drop(actual_circuit);
    if actual.local_rows != capacity_local_rows_v1(active_blocks)?
        || actual.execution.len() != capacity_memory_rows_v1(active_blocks)?
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let maximum_compute_rows = fixed_schedule.maximum_compute_rows;
    let actual_compute_rows = actual
        .local_rows
        .checked_sub(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
    if maximum_compute_rows
        != maximum_blocks * SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1
            + SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1
        || actual_compute_rows
            != active_blocks * SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1
                + SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let mut base_rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    let mut fixed_rows = Vec::new();
    base_rows
        .try_reserve_exact(maximum_logical_rows)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    fixed_rows
        .try_reserve_exact(maximum_logical_rows)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    for index in 0..maximum_local_rows {
        let active_compute = index < actual_compute_rows;
        let digest_index = index
            .checked_sub(maximum_compute_rows)
            .filter(|digest| *digest < SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1);
        let mut base = [F::ZERO; SHA_WORD_CAPACITY_BASE_WIDTH_V1];
        if active_compute {
            base[..SHA_WORD_BASE_WIDTH_V1]
                .copy_from_slice(&capacity_raw_base_row_v1(&actual.base_rows[index])?);
            base[SHA_WORD_CAPACITY_ROW_ACTIVE_V1] = F::ONE;
        } else if let Some(digest_index) = digest_index {
            let actual_index = actual_compute_rows + digest_index;
            base[..SHA_WORD_BASE_WIDTH_V1]
                .copy_from_slice(&capacity_raw_base_row_v1(&actual.base_rows[actual_index])?);
            base[SHA_WORD_CAPACITY_ROW_ACTIVE_V1] = F::ONE;
            let ShaWordFixedRowV1::Digest { address, .. } = actual
                .fixed_rows
                .get(actual_index)
                .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?
            else {
                return Err(ZkX509ShaWordStarkErrorV1::Topology);
            };
            base[SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1] =
                F(u64::try_from(*address).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
        }
        if index >= SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1 && index < maximum_compute_rows
        {
            let block_row = index
                .checked_sub(SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1)
                .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
            let block = block_row / SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1;
            base[SHA_WORD_CAPACITY_FINAL_BLOCK_V1] =
                F(u64::from(active_compute && block + 1 == active_blocks));
        }
        let fixed = fixed_schedule.fixed_row_v1(index)?;
        if active_compute && fixed[SHA_WORD_CAPACITY_INPUT_WORD_V1] == F::ONE {
            let input_word = usize::try_from(fixed[SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1].0)
                .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
            for byte in 0..4 {
                let byte_index = input_word
                    .checked_mul(4)
                    .and_then(|offset| offset.checked_add(byte))
                    .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
                if byte_index < message.len() {
                    base[SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + byte] = F::ONE;
                } else if byte_index == message.len() {
                    base[SHA_WORD_CAPACITY_MARKER_MASK_V1 + byte] = F::ONE;
                }
            }
        }
        base_rows.push(base);
        fixed_rows.push(fixed);
    }
    for value in actual.base_rows.iter_mut().flatten() {
        value.zeroize_v1();
    }
    drop(core::mem::take(&mut actual.base_rows));
    for fixed in &mut actual.fixed_rows {
        if let ShaWordFixedRowV1::Digest { expected, .. } = fixed {
            zeroize::Zeroize::zeroize(expected);
        }
    }
    drop(core::mem::take(&mut actual.fixed_rows));
    for memory_index in 0..maximum_memory_rows {
        let index = maximum_local_rows + memory_index;
        let memory_active = memory_index < actual.execution.len();
        let mut base = [F::ZERO; SHA_WORD_CAPACITY_BASE_WIDTH_V1];
        if memory_active {
            let execution = actual.execution[memory_index];
            let sorted = actual.sorted[memory_index];
            base[0] = execution.address;
            base[1] = execution.value;
            base[2] = execution.is_write;
            base[3] = sorted.address;
            base[4] = sorted.value;
            base[5] = sorted.is_write;
            base[SHA_WORD_CAPACITY_ROW_ACTIVE_V1] = F::ONE;
            base[SHA_WORD_CAPACITY_SORTED_SAME_NEXT_V1] = F(u64::from(
                actual
                    .sorted
                    .get(memory_index + 1)
                    .is_some_and(|next| next.address == sorted.address),
            ));
        }
        let fixed = fixed_schedule.fixed_row_v1(index)?;
        base_rows.push(base);
        fixed_rows.push(fixed);
    }
    drop(fixed_schedule);
    Ok(ZkX509ShaWordCapacityBaseSourceV1 {
        message_len: message.len(),
        #[cfg(test)]
        maximum_message_len,
        #[cfg(test)]
        exact_length,
        active_blocks,
        maximum_blocks,
        maximum_local_rows,
        maximum_memory_rows,
        actual_compute_rows,
        maximum_compute_rows,
        base_rows: base_rows.into_vec(),
        fixed_rows,
        local_events: core::mem::take(&mut actual.local_events),
        execution: core::mem::take(&mut actual.execution),
        sorted: core::mem::take(&mut actual.sorted),
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ShaWordCapacityBaseSourceV1 {
    fn bind_challenges_v1(
        self,
        challenges: ZkX509ShaWordStarkChallengesV1,
    ) -> Result<ZkX509ShaWordCapacityTraceV1, ZkX509ShaWordStarkErrorV1> {
        validate_zk_x509_sha_word_stark_challenges_v1(challenges)?;
        self.bind_memory_challenges_v1(challenges.memory)
    }
    fn bind_memory_challenges_v1(
        mut self,
        challenges: ZkX509WordMemoryChallengesV1,
    ) -> Result<ZkX509ShaWordCapacityTraceV1, ZkX509ShaWordStarkErrorV1> {
        validate_challenges(challenges)?;
        let maximum_logical_rows = self.logical_rows();
        let mut aux_rows = PrivateTableV1::new(
            vec![[F::ZERO; SHA_WORD_CAPACITY_AUX_WIDTH_V1]; maximum_logical_rows],
            zeroize_field_rows_v1,
        );
        let mut local_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
        for index in 0..self.maximum_local_rows {
            let events: &[WordMemoryAccessV1] = if index < self.actual_compute_rows {
                self.local_events
                    .get(index)
                    .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?
            } else if index >= self.maximum_compute_rows {
                self.local_events
                    .get(self.actual_compute_rows + index - self.maximum_compute_rows)
                    .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?
            } else {
                &[]
            };
            let (row, after) = local_product_row(events, local_product, challenges)?;
            aux_rows[index][..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1].copy_from_slice(&row);
            local_product = after;
        }
        let mut execution_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
        let mut sorted_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
        for memory_index in 0..self.maximum_memory_rows {
            let index = self.maximum_local_rows + memory_index;
            let mut row = [F::ZERO; SHA_WORD_MEMORY_PRODUCT_WIDTH_V1];
            row[MEMORY_EXEC_BEFORE..MEMORY_EXEC_BEFORE + SHA_WORD_COPY_LANES_V1]
                .copy_from_slice(&execution_product);
            row[MEMORY_SORT_BEFORE..MEMORY_SORT_BEFORE + SHA_WORD_COPY_LANES_V1]
                .copy_from_slice(&sorted_product);
            if memory_index < self.execution.len() {
                for lane in 0..SHA_WORD_COPY_LANES_V1 {
                    execution_product[lane] = execution_product[lane].mul(compress_access(
                        self.execution[memory_index],
                        challenges.lanes[lane],
                    ));
                    sorted_product[lane] = sorted_product[lane].mul(compress_access(
                        self.sorted[memory_index],
                        challenges.lanes[lane],
                    ));
                }
            }
            row[MEMORY_EXEC_AFTER..MEMORY_EXEC_AFTER + SHA_WORD_COPY_LANES_V1]
                .copy_from_slice(&execution_product);
            row[MEMORY_SORT_AFTER..MEMORY_SORT_AFTER + SHA_WORD_COPY_LANES_V1]
                .copy_from_slice(&sorted_product);
            aux_rows[index][..SHA_WORD_MEMORY_PRODUCT_WIDTH_V1].copy_from_slice(&row);
        }
        if execution_product != sorted_product || execution_product != local_product {
            return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
        }
        for row in aux_rows.iter_mut() {
            row[GLOBAL_LOCAL_PRODUCT_END..GLOBAL_LOCAL_PRODUCT_END + SHA_WORD_COPY_LANES_V1]
                .copy_from_slice(&local_product);
        }
        let mut message_count = F::ZERO;
        let mut padding_phase = F::ZERO;
        let mut active_block_count = F::ZERO;
        for index in 0..maximum_logical_rows {
            aux_rows[index][SHA_WORD_CAPACITY_MESSAGE_COUNT_V1] = message_count;
            aux_rows[index][SHA_WORD_CAPACITY_PADDING_PHASE_V1] = padding_phase;
            aux_rows[index][SHA_WORD_CAPACITY_ACTIVE_BLOCKS_V1] = active_block_count;
            if self.fixed_rows[index][SHA_WORD_CAPACITY_BLOCK_FIRST_V1] == F::ONE {
                active_block_count =
                    active_block_count.add(self.base_rows[index][SHA_WORD_CAPACITY_ROW_ACTIVE_V1]);
            }
            if self.fixed_rows[index][SHA_WORD_CAPACITY_INPUT_WORD_V1] == F::ONE
                && self.base_rows[index][SHA_WORD_CAPACITY_ROW_ACTIVE_V1] == F::ONE
            {
                for byte in 0..4 {
                    message_count = message_count
                        .add(self.base_rows[index][SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + byte]);
                    padding_phase = padding_phase
                        .add(self.base_rows[index][SHA_WORD_CAPACITY_MARKER_MASK_V1 + byte]);
                }
            }
        }
        if message_count
            != F(u64::try_from(self.message_len).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?)
            || padding_phase != F::ONE
            || active_block_count
                != F(u64::try_from(self.active_blocks)
                    .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?)
        {
            return Err(ZkX509ShaWordStarkErrorV1::Topology);
        }
        Ok(ZkX509ShaWordCapacityTraceV1 {
            message_len: self.message_len,
            #[cfg(test)]
            maximum_message_len: self.maximum_message_len,
            #[cfg(test)]
            exact_length: self.exact_length,
            active_blocks: self.active_blocks,
            #[cfg(test)]
            maximum_blocks: self.maximum_blocks,
            maximum_local_rows: self.maximum_local_rows,
            maximum_memory_rows: self.maximum_memory_rows,
            base_rows: core::mem::take(&mut self.base_rows),
            aux_rows: aux_rows.into_vec(),
            fixed_rows: core::mem::take(&mut self.fixed_rows),
        })
    }
}
/// Test-only focused builder retaining the pre-X5B1 word-memory API.
#[cfg(test)]
pub fn build_sha_word_capacity_trace_v1(
    message: &[u8],
    maximum_message_len: usize,
    exact_length: bool,
    challenges: ZkX509WordMemoryChallengesV1,
) -> Result<ZkX509ShaWordCapacityTraceV1, ZkX509ShaWordStarkErrorV1> {
    build_sha_word_capacity_base_source_v1(message, maximum_message_len, exact_length)?
        .bind_memory_challenges_v1(challenges)
}
fn read(address: WordIdV1, value: F) -> Result<WordMemoryAccessV1, ZkX509ShaWordStarkErrorV1> {
    Ok(WordMemoryAccessV1 {
        address: F(u64::try_from(address.0).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?),
        value,
        is_write: F::ZERO,
    })
}
fn write(address: WordIdV1, value: F) -> Result<WordMemoryAccessV1, ZkX509ShaWordStarkErrorV1> {
    Ok(WordMemoryAccessV1 {
        address: F(u64::try_from(address.0).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?),
        value,
        is_write: F::ONE,
    })
}
fn operation_output(operation: &WordOperationV1) -> WordIdV1 {
    match operation {
        WordOperationV1::Sigma { output, .. }
        | WordOperationV1::Choose { output, .. }
        | WordOperationV1::Majority { output, .. }
        | WordOperationV1::Add { output, .. } => *output,
    }
}
fn word_value(
    circuit: &ZkX509Sha256WordCircuitV1,
    id: WordIdV1,
) -> Result<F, ZkX509ShaWordStarkErrorV1> {
    circuit
        .stark_words_v1()
        .get(id.0)
        .map(|row| row.value)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)
}
fn input_fixed_bits(
    shape: &ZkX509Sha256WordCircuitV1,
    message_len: usize,
    address: usize,
) -> Result<[i8; 32], ZkX509ShaWordStarkErrorV1> {
    let mut fixed = [-1_i8; 32];
    if let Some(position) = shape
        .stark_input_words_v1()
        .iter()
        .position(|id| id.0 == address)
    {
        let row = shape
            .stark_words_v1()
            .get(address)
            .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
        for byte in 0..4 {
            let byte_offset = position
                .checked_mul(4)
                .and_then(|offset| offset.checked_add(byte))
                .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
            if byte_offset >= message_len {
                for within in 0..8 {
                    let bit = (3 - byte) * 8 + within;
                    fixed[bit] = i8::try_from(row.bits[bit].0)
                        .map_err(|_| ZkX509ShaWordStarkErrorV1::Topology)?;
                }
            }
        }
    } else {
        let row = shape
            .stark_words_v1()
            .get(address)
            .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
        for (target, bit) in fixed.iter_mut().zip(row.bits) {
            *target = i8::try_from(bit.0).map_err(|_| ZkX509ShaWordStarkErrorV1::Topology)?;
        }
    }
    Ok(fixed)
}
fn push_word_row(
    rows: &mut Vec<Vec<F>>,
    fixed: &mut Vec<ShaWordFixedRowV1>,
    events: &mut Vec<Vec<WordMemoryAccessV1>>,
    circuit: &ZkX509Sha256WordCircuitV1,
    shape: &ZkX509Sha256WordCircuitV1,
    address: usize,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    let word = circuit
        .stark_words_v1()
        .get(address)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
    let mut row = vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1];
    row[0] = word.value;
    row[1..33].copy_from_slice(&word.bits);
    rows.push(row);
    fixed.push(ShaWordFixedRowV1::Word {
        address,
        fixed_bits: input_fixed_bits(shape, circuit.stark_message_len_v1(), address)?,
    });
    events.push(vec![write(WordIdV1(address), word.value)?]);
    Ok(())
}
fn push_sigma_row(
    rows: &mut Vec<Vec<F>>,
    fixed: &mut Vec<ShaWordFixedRowV1>,
    events: &mut Vec<Vec<WordMemoryAccessV1>>,
    circuit: &ZkX509Sha256WordCircuitV1,
    input: WordIdV1,
    output: WordIdV1,
    rotate_first: u8,
    rotate_second: u8,
    third: SigmaThirdV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    let input_row = circuit
        .stark_words_v1()
        .get(input.0)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
    let output_row = circuit
        .stark_words_v1()
        .get(output.0)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
    let mut row = vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1];
    row[..32].copy_from_slice(&input_row.bits);
    row[32..64].copy_from_slice(&output_row.bits);
    rows.push(row);
    fixed.push(ShaWordFixedRowV1::Sigma {
        input: input.0,
        output: output.0,
        rotate_first,
        rotate_second,
        third,
    });
    events.push(vec![
        read(input, input_row.value)?,
        write(output, output_row.value)?,
    ]);
    Ok(())
}
fn push_boolean_rows(
    rows: &mut Vec<Vec<F>>,
    fixed: &mut Vec<ShaWordFixedRowV1>,
    events: &mut Vec<Vec<WordMemoryAccessV1>>,
    circuit: &ZkX509Sha256WordCircuitV1,
    addresses: [WordIdV1; 4],
    majority: bool,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    let words = addresses
        .iter()
        .copied()
        .map(|address| {
            circuit
                .stark_words_v1()
                .get(address.0)
                .copied()
                .ok_or(ZkX509ShaWordStarkErrorV1::Topology)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let words: [_; 4] = words
        .try_into()
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Topology)?;
    let mut accumulators = [F::ZERO; 4];
    for chunk in 0..4 {
        let mut row = vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1];
        for operand in 0..4 {
            row[operand] = words[operand].value;
            for within in 0..8 {
                let bit = chunk * 8 + within;
                let value = words[operand].bits[bit];
                row[4 + operand * 8 + within] = value;
                accumulators[operand] = accumulators[operand].add(value.mul(F(1_u64 << bit)));
            }
            row[36 + operand] = accumulators[operand];
        }
        rows.push(row);
        let addresses = addresses.map(|address| address.0);
        fixed.push(if majority {
            ShaWordFixedRowV1::Majority {
                addresses,
                chunk: u8::try_from(chunk).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?,
            }
        } else {
            ShaWordFixedRowV1::Choose {
                addresses,
                chunk: u8::try_from(chunk).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?,
            }
        });
        if chunk == 0 {
            events.push(vec![
                read(WordIdV1(addresses[0]), words[0].value)?,
                read(WordIdV1(addresses[1]), words[1].value)?,
                read(WordIdV1(addresses[2]), words[2].value)?,
                write(WordIdV1(addresses[3]), words[3].value)?,
            ]);
        } else {
            events.push(Vec::new());
        }
    }
    Ok(())
}
fn push_add_row(
    rows: &mut Vec<Vec<F>>,
    fixed: &mut Vec<ShaWordFixedRowV1>,
    events: &mut Vec<Vec<WordMemoryAccessV1>>,
    circuit: &ZkX509Sha256WordCircuitV1,
    inputs: [WordIdV1; 5],
    arity: u8,
    constant: u32,
    output: WordIdV1,
    carry_bits: [F; 3],
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if !(1..=5).contains(&arity) {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let mut row = vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1];
    let mut row_events = Vec::with_capacity(usize::from(arity) + 1);
    for index in 0..usize::from(arity) {
        row[index] = word_value(circuit, inputs[index])?;
        row_events.push(read(inputs[index], row[index])?);
    }
    row[5] = word_value(circuit, output)?;
    row[6..9].copy_from_slice(&carry_bits);
    let output_bits = circuit
        .stark_words_v1()
        .get(output.0)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?
        .bits;
    row[9..41].copy_from_slice(&output_bits);
    row_events.push(write(output, row[5])?);
    rows.push(row);
    fixed.push(ShaWordFixedRowV1::Add {
        inputs: inputs.map(|id| id.0),
        arity,
        constant,
        output: output.0,
    });
    events.push(row_events);
    Ok(())
}
fn push_operation_rows(
    rows: &mut Vec<Vec<F>>,
    fixed: &mut Vec<ShaWordFixedRowV1>,
    events: &mut Vec<Vec<WordMemoryAccessV1>>,
    circuit: &ZkX509Sha256WordCircuitV1,
    operation: &WordOperationV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    match operation {
        WordOperationV1::Sigma {
            input,
            rotate_first,
            rotate_second,
            third,
            output,
        } => push_sigma_row(
            rows,
            fixed,
            events,
            circuit,
            *input,
            *output,
            *rotate_first,
            *rotate_second,
            *third,
        ),
        WordOperationV1::Choose { x, y, z, output } => {
            push_boolean_rows(rows, fixed, events, circuit, [*x, *y, *z, *output], false)
        }
        WordOperationV1::Majority { x, y, z, output } => {
            push_boolean_rows(rows, fixed, events, circuit, [*x, *y, *z, *output], true)
        }
        WordOperationV1::Add {
            inputs,
            arity,
            constant,
            output,
            carry_bits,
            ..
        } => push_add_row(
            rows,
            fixed,
            events,
            circuit,
            *inputs,
            *arity,
            *constant,
            *output,
            *carry_bits,
        ),
    }
}
fn digest_words(digest: [u8; 32]) -> [u32; 8] {
    core::array::from_fn(|index| {
        u32::from_be_bytes(
            digest[index * 4..index * 4 + 4]
                .try_into()
                .expect("digest word is four bytes"),
        )
    })
}
/// Compile the challenge-independent local and word-memory base trace.
pub fn build_sha_word_stark_base_v1(
    statement: ZkX509ShaWordStarkStatementV1,
    message: &[u8],
) -> Result<ZkX509ShaWordStarkBaseV1, ZkX509ShaWordStarkErrorV1> {
    if message.len() != statement.message_len
        || statement.message_len > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let circuit = build_sha256_word_circuit_v1(message)?;
    if circuit.digest() != statement.digest {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let shape_message = vec![0_u8; statement.message_len];
    let shape = build_sha256_word_circuit_v1(&shape_message)?;
    if circuit.stark_words_v1().len() != shape.stark_words_v1().len()
        || circuit.stark_operations_v1().len() != shape.stark_operations_v1().len()
        || circuit
            .stark_operations_v1()
            .iter()
            .zip(shape.stark_operations_v1())
            .any(|(actual, expected)| !actual.same_topology(expected))
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let expected_blocks = capacity_blocks_v1(statement.message_len)?;
    let expected_rows = capacity_local_rows_v1(expected_blocks)?
        .checked_add(capacity_memory_rows_v1(expected_blocks)?)
        .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    let mut fixed = PrivateTableV1::new(Vec::new(), zeroize_sha_word_private_fixed_v1);
    let mut events = PrivateTableV1::new(Vec::new(), zeroize_sha_word_event_rows_v1);
    rows.try_reserve_exact(expected_rows)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    fixed
        .try_reserve_exact(expected_rows)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    events
        .try_reserve_exact(expected_rows)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    let mut word_cursor = 0_usize;
    let mut operation_outputs = BTreeSet::new();
    for operation in circuit.stark_operations_v1() {
        let output = operation_output(operation);
        if !operation_outputs.insert(output.0) || output.0 < word_cursor {
            return Err(ZkX509ShaWordStarkErrorV1::Topology);
        }
        while word_cursor < output.0 {
            push_word_row(
                &mut rows,
                &mut fixed,
                &mut events,
                &circuit,
                &shape,
                word_cursor,
            )?;
            word_cursor += 1;
        }
        push_operation_rows(&mut rows, &mut fixed, &mut events, &circuit, operation)?;
        word_cursor = output
            .0
            .checked_add(1)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
    }
    while word_cursor < circuit.stark_words_v1().len() {
        push_word_row(
            &mut rows,
            &mut fixed,
            &mut events,
            &circuit,
            &shape,
            word_cursor,
        )?;
        word_cursor += 1;
    }
    let output_ids = circuit.stark_output_words_v1();
    let expected_digest = digest_words(statement.digest);
    for (index, output) in output_ids.into_iter().enumerate() {
        let word = circuit
            .stark_words_v1()
            .get(output.0)
            .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
        let mut row = vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1];
        row[0] = word.value;
        row[1..33].copy_from_slice(&word.bits);
        rows.push(row);
        fixed.push(ShaWordFixedRowV1::Digest {
            address: output.0,
            expected: expected_digest[index],
        });
        events.push(vec![read(output, word.value)?]);
    }
    if rows.len() != fixed.len() || rows.len() != events.len() {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let local_rows = rows.len();
    let event_count = events.iter().try_fold(0_usize, |count, row| {
        count
            .checked_add(row.len())
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)
    })?;
    let mut execution = PrivateTableV1::new(Vec::new(), zeroize_sha_word_events_v1);
    execution
        .try_reserve_exact(event_count)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    for row in events.iter() {
        execution.extend_from_slice(row);
    }
    let mut sorted = PrivateTableV1::new(Vec::new(), zeroize_sha_word_events_v1);
    sorted
        .try_reserve_exact(event_count)
        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
    sorted.extend_from_slice(&execution);
    // Each word address has one immutable value. Equal address/write keys
    // therefore have identical event tuples; unstable sorting preserves the
    // canonical bytes without a heap scratch copy of private events.
    sorted.sort_unstable_by_key(|access| {
        (
            access.address.0,
            if access.is_write == F::ONE {
                0_u8
            } else {
                1_u8
            },
        )
    });
    if sorted.as_slice() != circuit.stark_memory_v1().sorted.as_slice() {
        return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
    }
    for index in 0..execution.len() {
        let mut row = vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1];
        row[0] = execution[index].address;
        row[1] = execution[index].value;
        row[2] = execution[index].is_write;
        row[3] = sorted[index].address;
        row[4] = sorted[index].value;
        row[5] = sorted[index].is_write;
        rows.push(row);
        let execution_address = usize::try_from(execution[index].address.0)
            .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
        let sorted_address = usize::try_from(sorted[index].address.0)
            .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?;
        fixed.push(ShaWordFixedRowV1::Memory {
            execution_address,
            execution_write: execution[index].is_write == F::ONE,
            sorted_address,
            sorted_write: sorted[index].is_write == F::ONE,
            sorted_same_address_next: sorted
                .get(index + 1)
                .is_some_and(|next| next.address == sorted[index].address),
            memory_first: index == 0,
            memory_last: index + 1 == execution.len(),
        });
        events.push(Vec::new());
    }
    let segment_rows = SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1;
    let total_rows = rows.len();
    if total_rows != expected_rows {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let segment_count = total_rows.div_ceil(segment_rows);
    if segment_count == 0 || segment_count > SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    #[cfg(test)]
    let active_rows_per_segment = (0..segment_count)
        .map(|segment| {
            total_rows
                .saturating_sub(segment * segment_rows)
                .min(segment_rows)
        })
        .collect();
    // The suffix contains only empty memory-row event vectors. Move the local
    // events into their clearing owner rather than cloning private event cells.
    events.truncate(local_rows);
    Ok(ZkX509ShaWordStarkBaseV1 {
        #[cfg(test)]
        statement,
        base_rows: rows.into_vec(),
        fixed_rows: fixed.into_vec(),
        local_events: events.into_vec(),
        execution: execution.into_vec(),
        sorted: sorted.into_vec(),
        local_rows,
        #[cfg(test)]
        segment_rows,
        #[cfg(test)]
        active_rows_per_segment,
    })
}
#[cfg(test)]
fn is_boolean(value: F) -> bool {
    value.mul(value.sub(F::ONE)) == F::ZERO
}
fn pack_bits<A: PolynomialAirFieldV1>(bits: &[A]) -> A {
    bits.iter()
        .copied()
        .enumerate()
        .fold(A::ZERO, |sum, (bit, value)| {
            sum.add(value.mul_base(F(1_u64 << bit)))
        })
}
fn xor_three<A: PolynomialAirFieldV1>(x: A, y: A, z: A) -> A {
    let xy = x.mul(y);
    let xz = x.mul(z);
    let yz = y.mul(z);
    x.add(y)
        .add(z)
        .sub(xy.add(xz).add(yz).mul_base(F(2)))
        .add(xy.mul(z).mul_base(F(4)))
}
#[cfg(test)]
fn ensure_canonical_fields(rows: &[Vec<F>], width: usize) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if rows.is_empty()
        || rows.iter().any(|row| {
            row.len() != width || row.iter().any(|value| F::canonical(value.0).is_none())
        })
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    Ok(())
}
#[cfg(test)]
fn ensure_zero_suffix(row: &[F], first_unused: usize) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if row
        .get(first_unused..)
        .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?
        .iter()
        .any(|value| *value != F::ZERO)
    {
        return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
    }
    Ok(())
}
#[cfg(test)]
fn validate_range_row(value: F, bits: &[F]) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if bits.len() != 32 || bits.iter().any(|bit| !is_boolean(*bit)) || pack_bits(bits) != value {
        return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
    }
    Ok(())
}
#[cfg(test)]
fn expected_fixed_topology(
    statement: ZkX509ShaWordStarkStatementV1,
) -> Result<ZkX509ShaWordStarkBaseV1, ZkX509ShaWordStarkErrorV1> {
    if statement.message_len > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    let shape_message = vec![0_u8; statement.message_len];
    let shape_circuit = build_sha256_word_circuit_v1(&shape_message)?;
    let shape_statement = ZkX509ShaWordStarkStatementV1 {
        message_len: statement.message_len,
        digest: shape_circuit.digest(),
    };
    let mut expected = build_sha_word_stark_base_v1(shape_statement, &shape_message)?;
    let digest = digest_words(statement.digest);
    let mut digest_index = 0_usize;
    for fixed in &mut expected.fixed_rows {
        if let ShaWordFixedRowV1::Digest { expected, .. } = fixed {
            *expected = *digest
                .get(digest_index)
                .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
            digest_index += 1;
        }
    }
    if digest_index != digest.len() {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    expected.statement = statement;
    Ok(expected)
}
fn aggregate_slots_v1(
    local_rows: usize,
    logical_rows: usize,
) -> Result<[ShaWordAggregateSlotV1; 2], ZkX509ShaWordStarkErrorV1> {
    if local_rows > logical_rows
        || local_rows > SHA_WORD_LOGICAL_SLOT_ROWS_V1
        || logical_rows > SHA_WORD_AGGREGATE_TRACE_SIZE_V1
    {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    let memory_rows = logical_rows - local_rows;
    let first_global_end = logical_rows.min(SHA_WORD_LOGICAL_SLOT_ROWS_V1);
    let first_local_end = local_rows.min(first_global_end);
    let first_memory_end = first_global_end.saturating_sub(local_rows).min(memory_rows);
    Ok([
        ShaWordAggregateSlotV1 {
            segment_index: 0,
            global_row_start: 0,
            global_row_end: first_global_end,
            local_row_start: 0,
            local_row_end: first_local_end,
            memory_row_start: 0,
            memory_row_end: first_memory_end,
        },
        ShaWordAggregateSlotV1 {
            segment_index: 1,
            global_row_start: first_global_end,
            global_row_end: logical_rows,
            local_row_start: first_local_end,
            local_row_end: local_rows,
            memory_row_start: first_memory_end,
            memory_row_end: memory_rows,
        },
    ])
}
/// Compile the verifier-owned logical topology for the canonical aggregate SHA-word adapter. The
/// returned schedule reconstructs any of the `2^20` fixed rows on demand.
#[cfg(test)]
pub fn compile_zk_x509_sha_word_stark_fixed_schedule_v1(
    statement: ZkX509ShaWordStarkStatementV1,
) -> Result<ZkX509ShaWordStarkFixedScheduleV1, ZkX509ShaWordStarkErrorV1> {
    let mut expected = expected_fixed_topology(statement)?;
    let logical_rows = expected.base_rows.len();
    if expected.segment_rows != SHA_WORD_LOGICAL_SLOT_ROWS_V1
        || logical_rows != expected.fixed_rows.len()
        || logical_rows != expected.local_rows + expected.execution.len()
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let slots = aggregate_slots_v1(expected.local_rows, logical_rows)?;
    Ok(ZkX509ShaWordStarkFixedScheduleV1 {
        #[cfg(test)]
        statement,
        fixed_rows: core::mem::take(&mut expected.fixed_rows),
        local_rows: expected.local_rows,
        logical_rows,
        slots,
    })
}
fn set_fixed_flag_v1(row: &mut [F; SHA_WORD_STARK_FIXED_WIDTH_V1], index: usize) {
    row[index] = F::ONE;
}
fn set_event_address_v1(
    row: &mut [F; SHA_WORD_STARK_FIXED_WIDTH_V1],
    slot: usize,
    address: usize,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    row[FIX_EVENT_ADDRESS + slot] =
        F(u64::try_from(address).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
    Ok(())
}
fn sigma_selector_v1(
    rotate_first: u8,
    rotate_second: u8,
    third: SigmaThirdV1,
) -> Result<usize, ZkX509ShaWordStarkErrorV1> {
    match (rotate_first, rotate_second, third) {
        (7, 18, SigmaThirdV1::Shift(3)) => Ok(FIX_SIGMA_SMALL_ZERO),
        (17, 19, SigmaThirdV1::Shift(10)) => Ok(FIX_SIGMA_SMALL_ONE),
        (2, 13, SigmaThirdV1::Rotate(22)) => Ok(FIX_SIGMA_BIG_ZERO),
        (6, 11, SigmaThirdV1::Rotate(25)) => Ok(FIX_SIGMA_BIG_ONE),
        _ => Err(ZkX509ShaWordStarkErrorV1::Topology),
    }
}
fn write_word_fixed_bytes_v1(
    row: &mut [F; SHA_WORD_STARK_FIXED_WIDTH_V1],
    fixed_bits: &[i8; 32],
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    for byte in 0..4 {
        let bits = &fixed_bits[byte * 8..(byte + 1) * 8];
        if bits.iter().all(|bit| *bit == -1) {
            continue;
        }
        if bits.iter().any(|bit| !matches!(*bit, 0 | 1)) {
            return Err(ZkX509ShaWordStarkErrorV1::Topology);
        }
        row[FIX_WORD_BYTE_MASK + byte] = F::ONE;
        row[FIX_WORD_BYTE_EXPECTED + byte] =
            bits.iter()
                .copied()
                .enumerate()
                .fold(F::ZERO, |packed, (bit, value)| {
                    packed.add(F(u64::try_from(value).expect("validated bit")).mul(F(1_u64 << bit)))
                });
    }
    Ok(())
}
fn write_continuation_public_v1(
    row: &mut [F; SHA_WORD_STARK_FIXED_WIDTH_V1],
    slot: ShaWordAggregateSlotV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    let values = [
        usize::from(slot.segment_index),
        slot.global_row_start,
        slot.global_row_end,
        slot.local_row_start,
        slot.local_row_end,
        slot.memory_row_start,
        slot.memory_row_end,
    ];
    for (target, value) in row[FIX_CONTINUATION_PUBLIC..FIX_CONTINUATION_PUBLIC + 7]
        .iter_mut()
        .zip(values)
    {
        *target = F(u64::try_from(value).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
    }
    Ok(())
}
impl ZkX509ShaWordStarkFixedScheduleV1 {
    /// Reconstruct one exact verifier-preprocessed row.
    pub(crate) fn fixed_row_v1(
        &self,
        index: usize,
    ) -> Result<[F; SHA_WORD_STARK_FIXED_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
        if index >= SHA_WORD_AGGREGATE_TRACE_SIZE_V1 {
            return Err(ZkX509ShaWordStarkErrorV1::Resource);
        }
        let mut row = [F::ZERO; SHA_WORD_STARK_FIXED_WIDTH_V1];
        let physical_slot = usize::from(index >= SHA_WORD_LOGICAL_SLOT_ROWS_V1);
        write_continuation_public_v1(&mut row, self.slots[physical_slot])?;
        if index == 0 {
            set_fixed_flag_v1(&mut row, FIX_FIRST_AGGREGATE_ROW);
        }
        if index + 1 == SHA_WORD_AGGREGATE_TRACE_SIZE_V1 {
            set_fixed_flag_v1(&mut row, FIX_LAST_AGGREGATE_ROW);
        }
        if index + 1 == SHA_WORD_LOGICAL_SLOT_ROWS_V1 {
            set_fixed_flag_v1(&mut row, FIX_PHYSICAL_BOUNDARY);
        } else if index + 1 < SHA_WORD_AGGREGATE_TRACE_SIZE_V1 {
            set_fixed_flag_v1(&mut row, FIX_CONTINUATION_WITHIN_SLOT);
        }
        let Some(fixed) = self.fixed_rows.get(index) else {
            set_fixed_flag_v1(&mut row, FIX_PADDING);
            return Ok(row);
        };
        if index == 0 {
            set_fixed_flag_v1(&mut row, FIX_LOCAL_FIRST);
        }
        if index < self.local_rows {
            if index + 1 < self.local_rows {
                set_fixed_flag_v1(&mut row, FIX_LOCAL_CONTINUE);
            } else {
                set_fixed_flag_v1(&mut row, FIX_LOCAL_LAST);
            }
        }
        match fixed {
            ShaWordFixedRowV1::Word {
                address,
                fixed_bits,
            } => {
                set_fixed_flag_v1(&mut row, FIX_WORD);
                write_word_fixed_bytes_v1(&mut row, fixed_bits)?;
                set_event_address_v1(&mut row, 0, *address)?;
            }
            ShaWordFixedRowV1::Sigma {
                input,
                output,
                rotate_first,
                rotate_second,
                third,
            } => {
                set_fixed_flag_v1(
                    &mut row,
                    sigma_selector_v1(*rotate_first, *rotate_second, *third)?,
                );
                set_event_address_v1(&mut row, 0, *input)?;
                set_event_address_v1(&mut row, 1, *output)?;
            }
            ShaWordFixedRowV1::Choose { addresses, chunk }
            | ShaWordFixedRowV1::Majority { addresses, chunk } => {
                set_fixed_flag_v1(
                    &mut row,
                    if matches!(fixed, ShaWordFixedRowV1::Choose { .. }) {
                        FIX_CHOOSE
                    } else {
                        FIX_MAJORITY
                    },
                );
                let chunk = usize::from(*chunk);
                if chunk >= 4 {
                    return Err(ZkX509ShaWordStarkErrorV1::Topology);
                }
                if chunk == 0 {
                    set_fixed_flag_v1(&mut row, FIX_BOOLEAN_FIRST);
                    for (slot, address) in addresses.iter().copied().enumerate() {
                        set_event_address_v1(&mut row, slot, address)?;
                    }
                }
                if chunk == 3 {
                    set_fixed_flag_v1(&mut row, FIX_BOOLEAN_LAST);
                } else {
                    set_fixed_flag_v1(&mut row, FIX_BOOLEAN_CONTINUE);
                }
                row[FIX_BOOLEAN_SCALE] = F(1_u64 << (chunk * 8));
                if chunk < 3 {
                    row[FIX_BOOLEAN_NEXT_SCALE] = F(1_u64 << ((chunk + 1) * 8));
                }
            }
            ShaWordFixedRowV1::Add {
                inputs,
                arity,
                constant,
                output,
            } => {
                let arity = usize::from(*arity);
                set_fixed_flag_v1(
                    &mut row,
                    match arity {
                        2 => FIX_ADD_ARITY_TWO,
                        4 => FIX_ADD_ARITY_FOUR,
                        _ => return Err(ZkX509ShaWordStarkErrorV1::Topology),
                    },
                );
                row[FIX_ADD_CONSTANT] = F(u64::from(*constant));
                for (slot, address) in inputs[..arity].iter().copied().enumerate() {
                    set_event_address_v1(&mut row, slot, address)?;
                }
                set_event_address_v1(&mut row, arity, *output)?;
            }
            ShaWordFixedRowV1::Digest { address, expected } => {
                set_fixed_flag_v1(&mut row, FIX_DIGEST);
                row[FIX_DIGEST_EXPECTED] = F(u64::from(*expected));
                set_event_address_v1(&mut row, 0, *address)?;
            }
            ShaWordFixedRowV1::Memory {
                execution_address,
                execution_write,
                sorted_address,
                sorted_write,
                sorted_same_address_next,
                ..
            } => {
                set_fixed_flag_v1(&mut row, FIX_MEMORY);
                row[FIX_MEMORY_EXECUTION_ADDRESS] = F(u64::try_from(*execution_address)
                    .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
                row[FIX_MEMORY_EXECUTION_WRITE] = F(u64::from(*execution_write));
                row[FIX_MEMORY_SORTED_ADDRESS] = F(u64::try_from(*sorted_address)
                    .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?);
                row[FIX_MEMORY_SORTED_WRITE] = F(u64::from(*sorted_write));
                let memory_index = index
                    .checked_sub(self.local_rows)
                    .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
                let slot = self.slots[physical_slot];
                if memory_index == slot.memory_row_start {
                    set_fixed_flag_v1(&mut row, FIX_MEMORY_FIRST_SEGMENT);
                }
                if memory_index + 1 == slot.memory_row_end {
                    set_fixed_flag_v1(&mut row, FIX_MEMORY_LAST_SEGMENT);
                }
                if index + 1 < self.logical_rows {
                    set_fixed_flag_v1(&mut row, FIX_MEMORY_CONTINUE);
                    set_fixed_flag_v1(
                        &mut row,
                        if *sorted_same_address_next {
                            FIX_MEMORY_SAME_NEXT
                        } else {
                            FIX_MEMORY_NEW_NEXT
                        },
                    );
                }
            }
            #[cfg(test)]
            ShaWordFixedRowV1::Padding => {
                return Err(ZkX509ShaWordStarkErrorV1::Topology);
            }
        }
        Ok(row)
    }
}
#[cfg(test)]
fn continuation_from_slot_v1(
    slot: ShaWordAggregateSlotV1,
    execution_product_start: [F; SHA_WORD_COPY_LANES_V1],
    execution_product_end: [F; SHA_WORD_COPY_LANES_V1],
    sorted_product_start: [F; SHA_WORD_COPY_LANES_V1],
    sorted_product_end: [F; SHA_WORD_COPY_LANES_V1],
) -> ShaWordPhysicalContinuationV1 {
    ShaWordPhysicalContinuationV1 {
        segment_index: slot.segment_index,
        global_row_start: slot.global_row_start,
        global_row_end: slot.global_row_end,
        local_row_start: slot.local_row_start,
        local_row_end: slot.local_row_end,
        memory_row_start: slot.memory_row_start,
        memory_row_end: slot.memory_row_end,
        execution_product_start,
        execution_product_end,
        sorted_product_start,
        sorted_product_end,
    }
}
#[cfg(test)]
fn aggregate_continuations_v1(
    schedule: &ZkX509ShaWordStarkFixedScheduleV1,
    trace: &ZkX509ShaWordStarkTraceV1,
) -> Result<
    (
        [ShaWordPhysicalContinuationV1; 2],
        [F; SHA_WORD_COPY_LANES_V1],
    ),
    ZkX509ShaWordStarkErrorV1,
> {
    if trace.base.statement != schedule.statement
        || trace.base.base_rows.len() != schedule.logical_rows
        || trace.aux_rows.len() != schedule.logical_rows
        || trace.continuations.is_empty()
        || trace.continuations.len() > 2
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let global_local_end: [F; SHA_WORD_COPY_LANES_V1] = trace
        .aux_rows
        .first()
        .and_then(|row| {
            row.get(GLOBAL_LOCAL_PRODUCT_END..GLOBAL_LOCAL_PRODUCT_END + SHA_WORD_COPY_LANES_V1)
        })
        .ok_or(ZkX509ShaWordStarkErrorV1::Continuation)?
        .try_into()
        .expect("four global local products");
    let first = *trace
        .continuations
        .first()
        .ok_or(ZkX509ShaWordStarkErrorV1::Continuation)?;
    let first = continuation_from_slot_v1(
        schedule.slots[0],
        first.execution_product_start,
        first.execution_product_end,
        first.sorted_product_start,
        first.sorted_product_end,
    );
    let second = if let Some(second) = trace.continuations.get(1).copied() {
        continuation_from_slot_v1(
            schedule.slots[1],
            second.execution_product_start,
            second.execution_product_end,
            second.sorted_product_start,
            second.sorted_product_end,
        )
    } else {
        continuation_from_slot_v1(
            schedule.slots[1],
            first.execution_product_end,
            first.execution_product_end,
            first.sorted_product_end,
            first.sorted_product_end,
        )
    };
    Ok(([first, second], global_local_end))
}
/// Reconstruct one aggregate base row, including canonical zero padding.
#[cfg(test)]
pub fn zk_x509_sha_word_stark_aggregate_base_row_v1(
    trace: &ZkX509ShaWordStarkTraceV1,
    index: usize,
) -> Result<[F; SHA_WORD_BASE_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
    if index >= SHA_WORD_AGGREGATE_TRACE_SIZE_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    match trace.base.base_rows.get(index) {
        Some(row) => row
            .as_slice()
            .try_into()
            .map_err(|_| ZkX509ShaWordStarkErrorV1::Topology),
        None => Ok([F::ZERO; SHA_WORD_BASE_WIDTH_V1]),
    }
}
/// Reconstruct one aggregate auxiliary row. Padding keeps only the exact
/// physical continuation tuple; every local/product cell is zero.
#[cfg(test)]
pub fn zk_x509_sha_word_stark_aggregate_aux_row_v1(
    schedule: &ZkX509ShaWordStarkFixedScheduleV1,
    trace: &ZkX509ShaWordStarkTraceV1,
    index: usize,
) -> Result<[F; SHA_WORD_AUX_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
    if index >= SHA_WORD_AGGREGATE_TRACE_SIZE_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    if let Some(row) = trace.aux_rows.get(index) {
        return row
            .as_slice()
            .try_into()
            .map_err(|_| ZkX509ShaWordStarkErrorV1::Topology);
    }
    let (continuations, global_local_end) = aggregate_continuations_v1(schedule, trace)?;
    let physical_slot = usize::from(index >= SHA_WORD_LOGICAL_SLOT_ROWS_V1);
    let mut row = [F::ZERO; SHA_WORD_AUX_WIDTH_V1];
    write_continuation(&mut row, continuations[physical_slot], global_local_end)?;
    Ok(row)
}
fn fixed_sum_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; SHA_WORD_STARK_FIXED_WIDTH_V1],
    indices: impl IntoIterator<Item = usize>,
) -> A {
    indices
        .into_iter()
        .fold(A::ZERO, |sum, index| sum.add(fixed[index]))
}
fn sigma_expected_bit_v1<A: PolynomialAirFieldV1>(
    input: &[A],
    bit: usize,
    rotate_first: usize,
    rotate_second: usize,
    third: SigmaThirdV1,
) -> A {
    let first = input[(bit + rotate_first) % 32];
    let second = input[(bit + rotate_second) % 32];
    let third = match third {
        SigmaThirdV1::Rotate(distance) => input[(bit + usize::from(distance)) % 32],
        SigmaThirdV1::Shift(distance) => input
            .get(bit + usize::from(distance))
            .copied()
            .unwrap_or(A::ZERO),
    };
    xor_three(first, second, third)
}
fn event_factor_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; SHA_WORD_STARK_FIXED_WIDTH_V1],
    slot: usize,
    value: A,
    is_write: bool,
    challenge: ZkX509WordMemoryLaneChallengesV1,
) -> A {
    A::from_base(challenge.beta)
        .add(fixed[FIX_EVENT_ADDRESS + slot].mul_base(challenge.address))
        .add(value.mul_base(challenge.value))
        .add(A::from_base(challenge.is_write.mul(F(u64::from(is_write)))))
}
fn local_pair_error_v1<A: PolynomialAirFieldV1>(
    pair: A,
    pair_slots: [usize; 2],
    fixed: &[A; SHA_WORD_STARK_FIXED_WIDTH_V1],
    values: [A; 6],
    writes: [bool; 6],
    event_count: usize,
    challenge: ZkX509WordMemoryLaneChallengesV1,
) -> A {
    let factor = |slot: usize| {
        if slot < event_count {
            event_factor_v1(fixed, slot, values[slot], writes[slot], challenge)
        } else {
            A::ONE
        }
    };
    pair.sub(factor(pair_slots[0]).mul(factor(pair_slots[1])))
}
fn memory_factor_v1<A: PolynomialAirFieldV1>(
    address: A,
    value: A,
    is_write: A,
    challenge: ZkX509WordMemoryLaneChallengesV1,
) -> A {
    A::from_base(challenge.beta)
        .add(address.mul_base(challenge.address))
        .add(value.mul_base(challenge.value))
        .add(is_write.mul_base(challenge.is_write))
}
/// Evaluate the canonical SHA-word aggregate AIR as a fixed-width polynomial
/// vector. Every semantic selector, public digest word, word address,
/// continuation label, and boundary gate is verifier-preprocessed numeric
/// material. The extension-domain evaluator never branches on a row enum.
///
/// The 441 base-only errors are folded with four independent challenges sampled after the base
/// commitment. Auxiliary constraints remain separate because the prover sees those challenges
/// before committing the auxiliary trace.
#[allow(clippy::too_many_lines)]
#[cfg(test)]
pub fn evaluate_zk_x509_sha_word_stark_residues_v1(
    current: &[F; SHA_WORD_BASE_WIDTH_V1],
    next: &[F; SHA_WORD_BASE_WIDTH_V1],
    current_aux: &[F; SHA_WORD_AUX_WIDTH_V1],
    next_aux: &[F; SHA_WORD_AUX_WIDTH_V1],
    fixed: &[F; SHA_WORD_STARK_FIXED_WIDTH_V1],
    challenges: ZkX509ShaWordStarkChallengesV1,
) -> Result<Vec<F>, ZkX509ShaWordStarkErrorV1> {
    evaluate_zk_x509_sha_word_stark_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
}
/// Evaluate the raw SHA-word polynomial over the base or extension field.
#[allow(clippy::too_many_lines)]
pub fn evaluate_zk_x509_sha_word_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; SHA_WORD_BASE_WIDTH_V1],
    next: &[A; SHA_WORD_BASE_WIDTH_V1],
    current_aux: &[A; SHA_WORD_AUX_WIDTH_V1],
    next_aux: &[A; SHA_WORD_AUX_WIDTH_V1],
    fixed: &[A; SHA_WORD_STARK_FIXED_WIDTH_V1],
    challenges: ZkX509ShaWordStarkChallengesV1,
) -> Result<Vec<A>, ZkX509ShaWordStarkErrorV1> {
    validate_zk_x509_sha_word_stark_challenges_v1(challenges)?;
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let word = fixed[FIX_WORD];
    let sigma_small_zero = fixed[FIX_SIGMA_SMALL_ZERO];
    let sigma_small_one = fixed[FIX_SIGMA_SMALL_ONE];
    let sigma_big_zero = fixed[FIX_SIGMA_BIG_ZERO];
    let sigma_big_one = fixed[FIX_SIGMA_BIG_ONE];
    let choose = fixed[FIX_CHOOSE];
    let majority = fixed[FIX_MAJORITY];
    let digest = fixed[FIX_DIGEST];
    let memory = fixed[FIX_MEMORY];
    let padding = fixed[FIX_PADDING];
    let sigma_any = fixed_sum_v1(
        fixed,
        [
            FIX_SIGMA_SMALL_ZERO,
            FIX_SIGMA_SMALL_ONE,
            FIX_SIGMA_BIG_ZERO,
            FIX_SIGMA_BIG_ONE,
        ],
    );
    let boolean_any = choose.add(majority);
    let add_any = fixed[FIX_ADD_ARITY_TWO].add(fixed[FIX_ADD_ARITY_FOUR]);
    let word_or_digest = word.add(digest);
    let local = word_or_digest.add(sigma_any).add(boolean_any).add(add_any);
    let mut folded_base = [A::ZERO; SHA_WORD_COPY_LANES_V1];
    let mut base_error_count = 0_usize;
    let mut push_base_error = |error: A| {
        for (folded, challenge) in folded_base.iter_mut().zip(challenges.base_folding) {
            *folded = folded.mul_base(challenge).add(error);
        }
        base_error_count += 1;
    };
    for column in 33..SHA_WORD_BASE_WIDTH_V1 {
        push_base_error(word_or_digest.mul(current[column]));
    }
    for column in 40..SHA_WORD_BASE_WIDTH_V1 {
        push_base_error(boolean_any.mul(current[column]));
    }
    for column in 41..SHA_WORD_BASE_WIDTH_V1 {
        push_base_error(add_any.mul(current[column]));
    }
    for column in 6..SHA_WORD_BASE_WIDTH_V1 {
        push_base_error(memory.mul(current[column]));
    }
    for value in current {
        push_base_error(padding.mul(*value));
    }
    let mut word_value = A::ZERO;
    for bit in 0..32 {
        let value = current[1 + bit];
        push_base_error(word_or_digest.mul(value.mul(value.sub(A::ONE))));
        word_value = word_value.add(value.mul(A::from_base(F(1_u64 << bit))));
    }
    push_base_error(word_or_digest.mul(current[0].sub(word_value)));
    for byte in 0..4 {
        let byte_value = pack_bits(&current[1 + byte * 8..1 + (byte + 1) * 8]);
        push_base_error(
            fixed[FIX_WORD_BYTE_MASK + byte]
                .mul(byte_value.sub(fixed[FIX_WORD_BYTE_EXPECTED + byte])),
        );
    }
    push_base_error(digest.mul(current[0].sub(fixed[FIX_DIGEST_EXPECTED])));
    for value in current {
        push_base_error(sigma_any.mul(value.mul(value.sub(A::ONE))));
    }
    for bit in 0..32 {
        let mut error = sigma_any.mul(current[32 + bit]);
        for (selector, rotate_first, rotate_second, third) in [
            (sigma_small_zero, 7_usize, 18_usize, SigmaThirdV1::Shift(3)),
            (sigma_small_one, 17_usize, 19_usize, SigmaThirdV1::Shift(10)),
            (sigma_big_zero, 2_usize, 13_usize, SigmaThirdV1::Rotate(22)),
            (sigma_big_one, 6_usize, 11_usize, SigmaThirdV1::Rotate(25)),
        ] {
            error = error.sub(selector.mul(sigma_expected_bit_v1(
                &current[..32],
                bit,
                rotate_first,
                rotate_second,
                third,
            )));
        }
        push_base_error(error);
    }
    for bit in &current[4..36] {
        push_base_error(boolean_any.mul(bit.mul(bit.sub(A::ONE))));
    }
    for within in 0..8 {
        let x = current[4 + within];
        let y = current[12 + within];
        let z = current[20 + within];
        let output = current[28 + within];
        let choose_value = x.mul(y).add(A::ONE.sub(x).mul(z));
        let xy = x.mul(y);
        let xz = x.mul(z);
        let yz = y.mul(z);
        let majority_value = xy.add(xz).add(yz).sub(A::from_base(F(2)).mul(xy.mul(z)));
        push_base_error(
            boolean_any
                .mul(output)
                .sub(choose.mul(choose_value))
                .sub(majority.mul(majority_value)),
        );
    }
    let boolean_first = boolean_any.mul(fixed[FIX_BOOLEAN_FIRST]);
    let boolean_continue = boolean_any.mul(fixed[FIX_BOOLEAN_CONTINUE]);
    let boolean_last = boolean_any.mul(fixed[FIX_BOOLEAN_LAST]);
    for operand in 0..4 {
        push_base_error(boolean_continue.mul(next[operand].sub(current[operand])));
        let contribution = current[4 + operand * 8..4 + (operand + 1) * 8]
            .iter()
            .copied()
            .enumerate()
            .fold(A::ZERO, |sum, (within, bit)| {
                sum.add(bit.mul(A::from_base(F(1_u64 << within))))
            })
            .mul(fixed[FIX_BOOLEAN_SCALE]);
        push_base_error(boolean_first.mul(current[36 + operand].sub(contribution)));
        let next_contribution = next[4 + operand * 8..4 + (operand + 1) * 8]
            .iter()
            .copied()
            .enumerate()
            .fold(A::ZERO, |sum, (within, bit)| {
                sum.add(bit.mul(A::from_base(F(1_u64 << within))))
            })
            .mul(fixed[FIX_BOOLEAN_NEXT_SCALE]);
        push_base_error(
            boolean_continue
                .mul(next[36 + operand].sub(current[36 + operand].add(next_contribution))),
        );
        push_base_error(boolean_last.mul(current[36 + operand].sub(current[operand])));
    }
    for bit in &current[6..9] {
        push_base_error(add_any.mul(bit.mul(bit.sub(A::ONE))));
    }
    let mut add_output = A::ZERO;
    for bit in 0..32 {
        let value = current[9 + bit];
        push_base_error(add_any.mul(value.mul(value.sub(A::ONE))));
        add_output = add_output.add(value.mul(A::from_base(F(1_u64 << bit))));
    }
    push_base_error(add_any.mul(current[5].sub(add_output)));
    push_base_error(fixed[FIX_ADD_ARITY_TWO].mul(current[2]));
    push_base_error(fixed[FIX_ADD_ARITY_TWO].mul(current[3]));
    push_base_error(add_any.mul(current[4]));
    let carry = current[6]
        .add(A::from_base(F(2)).mul(current[7]))
        .add(A::from_base(F(4)).mul(current[8]));
    let add_sum = current[..5]
        .iter()
        .copied()
        .fold(A::ZERO, A::add)
        .add(fixed[FIX_ADD_CONSTANT]);
    push_base_error(
        add_any.mul(
            add_sum
                .sub(current[5])
                .sub(A::from_base(F(1_u64 << 32)).mul(carry)),
        ),
    );
    push_base_error(memory.mul(current[2].mul(current[2].sub(A::ONE))));
    push_base_error(memory.mul(current[5].mul(current[5].sub(A::ONE))));
    push_base_error(memory.mul(current[0].sub(fixed[FIX_MEMORY_EXECUTION_ADDRESS])));
    push_base_error(memory.mul(current[2].sub(fixed[FIX_MEMORY_EXECUTION_WRITE])));
    push_base_error(memory.mul(current[3].sub(fixed[FIX_MEMORY_SORTED_ADDRESS])));
    push_base_error(memory.mul(current[5].sub(fixed[FIX_MEMORY_SORTED_WRITE])));
    let memory_same = fixed[FIX_MEMORY_SAME_NEXT];
    push_base_error(memory_same.mul(next[3].sub(current[3])));
    push_base_error(memory_same.mul(next[4].sub(current[4])));
    push_base_error(memory_same.mul(next[5]));
    let memory_new = fixed[FIX_MEMORY_NEW_NEXT];
    push_base_error(memory_new.mul(next[3].sub(current[3].add(A::ONE))));
    push_base_error(memory_new.mul(next[5].sub(A::ONE)));
    if base_error_count != SHA_WORD_STARK_BASE_ERROR_COUNT_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let mut residues = Vec::with_capacity(SHA_WORD_STARK_CONSTRAINT_COUNT_V1);
    residues.extend(folded_base);
    for lane in 0..SHA_WORD_COPY_LANES_V1 {
        let challenge = challenges.memory.lanes[lane];
        let packed_input = pack_bits(&current[..32]);
        let packed_output = pack_bits(&current[32..64]);
        let pair_descriptors = [
            (LOCAL_PAIR_01, [0_usize, 1_usize]),
            (LOCAL_PAIR_23, [2_usize, 3_usize]),
            (LOCAL_PAIR_45, [4_usize, 5_usize]),
        ];
        for (pair_offset, pair_slots) in pair_descriptors {
            let pair = current_aux[pair_offset + lane];
            let mut error = word.mul(local_pair_error_v1(
                pair,
                pair_slots,
                fixed,
                [current[0], A::ZERO, A::ZERO, A::ZERO, A::ZERO, A::ZERO],
                [true, false, false, false, false, false],
                1,
                challenge,
            ));
            error = error.add(digest.mul(local_pair_error_v1(
                pair,
                pair_slots,
                fixed,
                [current[0], A::ZERO, A::ZERO, A::ZERO, A::ZERO, A::ZERO],
                [false; 6],
                1,
                challenge,
            )));
            error = error.add(sigma_any.mul(local_pair_error_v1(
                pair,
                pair_slots,
                fixed,
                [
                    packed_input,
                    packed_output,
                    A::ZERO,
                    A::ZERO,
                    A::ZERO,
                    A::ZERO,
                ],
                [false, true, false, false, false, false],
                2,
                challenge,
            )));
            error = error.add(boolean_first.mul(local_pair_error_v1(
                pair,
                pair_slots,
                fixed,
                [
                    current[0],
                    current[1],
                    current[2],
                    current[3],
                    A::ZERO,
                    A::ZERO,
                ],
                [false, false, false, true, false, false],
                4,
                challenge,
            )));
            for (selector, arity) in [(FIX_ADD_ARITY_TWO, 2_usize), (FIX_ADD_ARITY_FOUR, 4)] {
                let mut values = [A::ZERO; 6];
                let mut writes = [false; 6];
                values[..arity].copy_from_slice(&current[..arity]);
                values[arity] = current[5];
                writes[arity] = true;
                error = error.add(fixed[selector].mul(local_pair_error_v1(
                    pair,
                    pair_slots,
                    fixed,
                    values,
                    writes,
                    arity + 1,
                    challenge,
                )));
            }
            let no_events = boolean_any.mul(A::ONE.sub(fixed[FIX_BOOLEAN_FIRST]));
            error = error.add(no_events.mul(pair.sub(A::ONE)));
            residues.push(error);
        }
        residues.push(
            local.mul(
                current_aux[LOCAL_QUAD + lane]
                    .sub(current_aux[LOCAL_PAIR_01 + lane].mul(current_aux[LOCAL_PAIR_23 + lane])),
            ),
        );
        residues.push(
            local.mul(
                current_aux[LOCAL_PRODUCT_AFTER + lane].sub(
                    current_aux[LOCAL_PRODUCT_BEFORE + lane]
                        .mul(current_aux[LOCAL_QUAD + lane])
                        .mul(current_aux[LOCAL_PAIR_45 + lane]),
                ),
            ),
        );
        residues
            .push(fixed[FIX_LOCAL_FIRST].mul(current_aux[LOCAL_PRODUCT_BEFORE + lane].sub(A::ONE)));
        residues.push(fixed[FIX_LOCAL_CONTINUE].mul(
            next_aux[LOCAL_PRODUCT_BEFORE + lane].sub(current_aux[LOCAL_PRODUCT_AFTER + lane]),
        ));
        residues.push(
            fixed[FIX_LOCAL_LAST].mul(
                current_aux[LOCAL_PRODUCT_AFTER + lane]
                    .sub(current_aux[GLOBAL_LOCAL_PRODUCT_END + lane]),
            ),
        );
        let execution_factor = memory_factor_v1(current[0], current[1], current[2], challenge);
        let sorted_factor = memory_factor_v1(current[3], current[4], current[5], challenge);
        residues.push(
            memory.mul(
                current_aux[MEMORY_EXEC_AFTER + lane]
                    .sub(current_aux[MEMORY_EXEC_BEFORE + lane].mul(execution_factor)),
            ),
        );
        residues.push(
            memory.mul(
                current_aux[MEMORY_SORT_AFTER + lane]
                    .sub(current_aux[MEMORY_SORT_BEFORE + lane].mul(sorted_factor)),
            ),
        );
        residues.push(
            fixed[FIX_MEMORY_CONTINUE].mul(
                next_aux[MEMORY_EXEC_BEFORE + lane].sub(current_aux[MEMORY_EXEC_AFTER + lane]),
            ),
        );
        residues.push(
            fixed[FIX_MEMORY_CONTINUE].mul(
                next_aux[MEMORY_SORT_BEFORE + lane].sub(current_aux[MEMORY_SORT_AFTER + lane]),
            ),
        );
        residues.push(
            fixed[FIX_MEMORY_FIRST_SEGMENT].mul(
                current_aux[MEMORY_EXEC_BEFORE + lane].sub(current_aux[CONT_EXEC_START + lane]),
            ),
        );
        residues.push(
            fixed[FIX_MEMORY_FIRST_SEGMENT].mul(
                current_aux[MEMORY_SORT_BEFORE + lane].sub(current_aux[CONT_SORT_START + lane]),
            ),
        );
        residues.push(
            fixed[FIX_MEMORY_LAST_SEGMENT]
                .mul(current_aux[MEMORY_EXEC_AFTER + lane].sub(current_aux[CONT_EXEC_END + lane])),
        );
        residues.push(
            fixed[FIX_MEMORY_LAST_SEGMENT]
                .mul(current_aux[MEMORY_SORT_AFTER + lane].sub(current_aux[CONT_SORT_END + lane])),
        );
        residues.push(
            fixed[FIX_LAST_AGGREGATE_ROW]
                .mul(current_aux[CONT_EXEC_END + lane].sub(current_aux[CONT_SORT_END + lane])),
        );
        residues.push(fixed[FIX_LAST_AGGREGATE_ROW].mul(
            current_aux[GLOBAL_LOCAL_PRODUCT_END + lane].sub(current_aux[CONT_EXEC_END + lane]),
        ));
        residues.push(
            fixed[FIX_FIRST_AGGREGATE_ROW].mul(current_aux[CONT_EXEC_START + lane].sub(A::ONE)),
        );
        residues.push(
            fixed[FIX_FIRST_AGGREGATE_ROW].mul(current_aux[CONT_SORT_START + lane].sub(A::ONE)),
        );
        residues.push(
            fixed[FIX_PHYSICAL_BOUNDARY]
                .mul(next_aux[CONT_EXEC_START + lane].sub(current_aux[CONT_EXEC_END + lane])),
        );
        residues.push(
            fixed[FIX_PHYSICAL_BOUNDARY]
                .mul(next_aux[CONT_SORT_START + lane].sub(current_aux[CONT_SORT_END + lane])),
        );
        residues.push(
            fixed[FIX_PHYSICAL_BOUNDARY].mul(
                next_aux[GLOBAL_LOCAL_PRODUCT_END + lane]
                    .sub(current_aux[GLOBAL_LOCAL_PRODUCT_END + lane]),
            ),
        );
    }
    for index in 0..7 {
        residues.push(
            current_aux[CONT_SEGMENT_INDEX + index].sub(fixed[FIX_CONTINUATION_PUBLIC + index]),
        );
    }
    for index in CONT_EXEC_START..SHA_WORD_AUX_WIDTH_V1 {
        residues
            .push(fixed[FIX_CONTINUATION_WITHIN_SLOT].mul(next_aux[index].sub(current_aux[index])));
    }
    for value in &current_aux[..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1] {
        residues.push(padding.mul(*value));
    }
    for value in &current_aux[SHA_WORD_MEMORY_PRODUCT_WIDTH_V1..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1] {
        residues.push(memory.mul(*value));
    }
    if residues.len() != SHA_WORD_STARK_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    Ok(residues)
}
/// Evaluate the fixed-capacity SHA-word relation for one opened row.
///
/// The raw 64/51/55 word AIR is retained for active local operations.  This
/// layer supplies private active/final-block selectors, dynamic SHA padding,
/// the selected final-state address, and independently gated execution and
/// sorted-memory tables.  No actual length or block count is verifier-fixed.
#[cfg(test)]
pub fn evaluate_zk_x509_sha_word_capacity_residues_v1(
    current: &[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1],
    next: &[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1],
    current_aux: &[F; SHA_WORD_CAPACITY_AUX_WIDTH_V1],
    next_aux: &[F; SHA_WORD_CAPACITY_AUX_WIDTH_V1],
    fixed: &[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1],
    challenges: ZkX509ShaWordStarkChallengesV1,
) -> Result<Vec<F>, ZkX509ShaWordStarkErrorV1> {
    evaluate_zk_x509_sha_word_capacity_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
}
/// Evaluate all 335 capacity residues over the base or extension field.
///
/// This shares the complete polynomial implementation with the scalar API. It
/// does not implement the enclosing SHA call-bus AIR or enable a MAIN Fp4 proof.
#[allow(clippy::too_many_lines)]
pub fn evaluate_zk_x509_sha_word_capacity_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; SHA_WORD_CAPACITY_BASE_WIDTH_V1],
    next: &[A; SHA_WORD_CAPACITY_BASE_WIDTH_V1],
    current_aux: &[A; SHA_WORD_CAPACITY_AUX_WIDTH_V1],
    next_aux: &[A; SHA_WORD_CAPACITY_AUX_WIDTH_V1],
    fixed: &[A; SHA_WORD_CAPACITY_FIXED_WIDTH_V1],
    challenges: ZkX509ShaWordStarkChallengesV1,
) -> Result<Vec<A>, ZkX509ShaWordStarkErrorV1> {
    validate_zk_x509_sha_word_stark_challenges_v1(challenges)?;
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let row_active = current[SHA_WORD_CAPACITY_ROW_ACTIVE_V1];
    let next_active = next[SHA_WORD_CAPACITY_ROW_ACTIVE_V1];
    let final_block = current[SHA_WORD_CAPACITY_FINAL_BLOCK_V1];
    let next_final_block = next[SHA_WORD_CAPACITY_FINAL_BLOCK_V1];
    let sorted_same_next = current[SHA_WORD_CAPACITY_SORTED_SAME_NEXT_V1];
    let input_word = fixed[SHA_WORD_CAPACITY_INPUT_WORD_V1];
    let digest = fixed[FIX_DIGEST];
    let memory = fixed[FIX_MEMORY];
    let local_compute = fixed_sum_v1(
        fixed[..SHA_WORD_STARK_FIXED_WIDTH_V1]
            .try_into()
            .expect("raw fixed prefix"),
        [
            FIX_WORD,
            FIX_SIGMA_SMALL_ZERO,
            FIX_SIGMA_SMALL_ONE,
            FIX_SIGMA_BIG_ZERO,
            FIX_SIGMA_BIG_ONE,
            FIX_CHOOSE,
            FIX_MAJORITY,
            FIX_ADD_ARITY_TWO,
            FIX_ADD_ARITY_FOUR,
        ],
    );
    let mut effective_fixed: [A; SHA_WORD_STARK_FIXED_WIDTH_V1] = fixed
        [..SHA_WORD_STARK_FIXED_WIDTH_V1]
        .try_into()
        .expect("raw fixed prefix");
    for selector in [
        FIX_WORD,
        FIX_SIGMA_SMALL_ZERO,
        FIX_SIGMA_SMALL_ONE,
        FIX_SIGMA_BIG_ZERO,
        FIX_SIGMA_BIG_ONE,
        FIX_CHOOSE,
        FIX_MAJORITY,
        FIX_ADD_ARITY_TWO,
        FIX_ADD_ARITY_FOUR,
        FIX_DIGEST,
    ] {
        effective_fixed[selector] = effective_fixed[selector].mul(row_active);
    }
    effective_fixed[FIX_MEMORY] = A::ZERO;
    effective_fixed[FIX_PADDING] = A::ZERO;
    for selector in [
        FIX_MEMORY_CONTINUE,
        FIX_MEMORY_SAME_NEXT,
        FIX_MEMORY_NEW_NEXT,
        FIX_MEMORY_FIRST_SEGMENT,
        FIX_MEMORY_LAST_SEGMENT,
        FIX_FIRST_AGGREGATE_ROW,
        FIX_LAST_AGGREGATE_ROW,
        FIX_PHYSICAL_BOUNDARY,
        FIX_CONTINUATION_WITHIN_SLOT,
    ] {
        effective_fixed[selector] = A::ZERO;
    }
    for byte in 0..4 {
        effective_fixed[FIX_WORD_BYTE_MASK + byte] = effective_fixed[FIX_WORD_BYTE_MASK + byte]
            .mul(row_active)
            .mul(A::ONE.sub(input_word));
    }
    effective_fixed[FIX_DIGEST_EXPECTED] = current[0];
    // FIX_DIGEST is Boolean only on the native schedule. Its LDE and OODS
    // values must select algebraically; an equality branch changes the AIR.
    effective_fixed[FIX_EVENT_ADDRESS] = digest
        .mul(current[SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1])
        .add(A::ONE.sub(digest).mul(effective_fixed[FIX_EVENT_ADDRESS]));
    for index in 0..7 {
        effective_fixed[FIX_CONTINUATION_PUBLIC + index] = current_aux[CONT_SEGMENT_INDEX + index];
    }
    let current_raw: &[A; SHA_WORD_BASE_WIDTH_V1] = current[..SHA_WORD_BASE_WIDTH_V1]
        .try_into()
        .expect("raw base prefix");
    let next_raw: &[A; SHA_WORD_BASE_WIDTH_V1] = next[..SHA_WORD_BASE_WIDTH_V1]
        .try_into()
        .expect("raw base prefix");
    let current_aux_raw: &[A; SHA_WORD_AUX_WIDTH_V1] = current_aux[..SHA_WORD_AUX_WIDTH_V1]
        .try_into()
        .expect("raw aux prefix");
    let next_aux_raw: &[A; SHA_WORD_AUX_WIDTH_V1] = next_aux[..SHA_WORD_AUX_WIDTH_V1]
        .try_into()
        .expect("raw aux prefix");
    let mut residues = evaluate_zk_x509_sha_word_stark_residues_over_field_v1(
        current_raw,
        next_raw,
        current_aux_raw,
        next_aux_raw,
        &effective_fixed,
        challenges,
    )?;
    let boolean_error = |value: A| value.mul(value.sub(A::ONE));
    residues.push(boolean_error(row_active));
    residues.push(boolean_error(final_block));
    residues.push(boolean_error(sorted_same_next));
    residues.push(final_block.mul(A::ONE.sub(row_active)));
    for byte in 0..4 {
        let message = current[SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + byte];
        let marker = current[SHA_WORD_CAPACITY_MARKER_MASK_V1 + byte];
        residues.push(boolean_error(message));
        residues.push(boolean_error(marker));
        residues.push(message.mul(marker));
        residues.push(message.mul(A::ONE.sub(fixed[SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1 + byte])));
        residues.push(A::ONE.sub(row_active).mul(message));
        residues.push(A::ONE.sub(row_active).mul(marker));
    }
    residues.push(A::ONE.sub(memory).mul(sorted_same_next));
    residues.push(A::ONE.sub(local_compute).mul(final_block));
    for byte in 0..4 {
        residues.push(
            A::ONE
                .sub(input_word)
                .mul(current[SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + byte]),
        );
        residues.push(
            A::ONE
                .sub(input_word)
                .mul(current[SHA_WORD_CAPACITY_MARKER_MASK_V1 + byte]),
        );
    }
    residues.push(
        A::ONE
            .sub(digest)
            .mul(current[SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1]),
    );
    residues.push(digest.mul(row_active.sub(A::ONE)));
    let inactive_compute = local_compute.mul(A::ONE.sub(row_active));
    let inactive_memory = memory.mul(A::ONE.sub(row_active));
    let mut folded_inactive_compute = [A::ZERO; SHA_WORD_COPY_LANES_V1];
    let mut folded_inactive_memory = [A::ZERO; SHA_WORD_COPY_LANES_V1];
    for value in current_raw {
        for lane in 0..SHA_WORD_COPY_LANES_V1 {
            folded_inactive_compute[lane] = folded_inactive_compute[lane]
                .mul_base(challenges.base_folding[lane])
                .add(inactive_compute.mul(*value));
            folded_inactive_memory[lane] = folded_inactive_memory[lane]
                .mul_base(challenges.base_folding[lane])
                .add(inactive_memory.mul(*value));
        }
    }
    residues.extend(folded_inactive_compute);
    residues.extend(folded_inactive_memory);
    let block_first = fixed[SHA_WORD_CAPACITY_BLOCK_FIRST_V1];
    let block_continue = fixed[SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1];
    let block_last = fixed[SHA_WORD_CAPACITY_BLOCK_LAST_V1];
    let maximum_block_last = fixed[SHA_WORD_CAPACITY_MAX_BLOCK_LAST_V1];
    residues.push(block_continue.mul(next_active.sub(row_active)));
    residues.push(block_continue.mul(next_final_block.sub(final_block)));
    residues.push(fixed[SHA_WORD_CAPACITY_CALL_FIRST_V1].mul(row_active.sub(A::ONE)));
    residues.push(
        block_last
            .mul(A::ONE.sub(maximum_block_last))
            .mul(final_block.sub(row_active.mul(A::ONE.sub(next_active)))),
    );
    residues.push(
        block_last
            .mul(A::ONE.sub(maximum_block_last))
            .mul(next_active)
            .mul(A::ONE.sub(row_active)),
    );
    residues.push(maximum_block_last.mul(final_block.sub(row_active)));
    let message_count = current_aux[SHA_WORD_CAPACITY_MESSAGE_COUNT_V1];
    let next_message_count = next_aux[SHA_WORD_CAPACITY_MESSAGE_COUNT_V1];
    let padding_phase = current_aux[SHA_WORD_CAPACITY_PADDING_PHASE_V1];
    let next_padding_phase = next_aux[SHA_WORD_CAPACITY_PADDING_PHASE_V1];
    let active_blocks = current_aux[SHA_WORD_CAPACITY_ACTIVE_BLOCKS_V1];
    let next_active_blocks = next_aux[SHA_WORD_CAPACITY_ACTIVE_BLOCKS_V1];
    let call_first = fixed[SHA_WORD_CAPACITY_CALL_FIRST_V1];
    let call_last = fixed[SHA_WORD_CAPACITY_CALL_LAST_V1];
    // Every logical call row has one public operation selector, including
    // privately inactive capacity rows. Physical padding has none. This linear
    // gate keeps carries within a call and excludes the cyclic padding wrap.
    let call_continue = local_compute.add(digest).add(memory).sub(call_last);
    residues.push(boolean_error(padding_phase));
    residues.push(call_first.mul(message_count));
    residues.push(call_first.mul(padding_phase));
    residues.push(call_first.mul(active_blocks));
    residues.push(call_last.mul(padding_phase.sub(A::ONE)));
    residues.push(
        call_last
            .mul(fixed[SHA_WORD_CAPACITY_EXACT_LENGTH_V1])
            .mul(message_count.sub(fixed[SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1])),
    );
    residues.push(
        call_continue.mul(next_active_blocks.sub(active_blocks.add(block_first.mul(row_active)))),
    );
    let mut phase_after = padding_phase;
    let mut message_increment = A::ZERO;
    let mut marker_increment = A::ZERO;
    let length_word = fixed[SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1]
        .add(fixed[SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1]);
    let length_gate = input_word.mul(row_active).mul(final_block).mul(length_word);
    let ordinary_gate = input_word
        .mul(row_active)
        .mul(A::ONE.sub(final_block.mul(length_word)));
    for byte in 0..4 {
        let message = current[SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + byte];
        let marker = current[SHA_WORD_CAPACITY_MARKER_MASK_V1 + byte];
        let bits_start = 1 + (3 - byte) * 8;
        let byte_value = pack_bits(&current[bits_start..bits_start + 8]);
        residues.push(ordinary_gate.mul(message.add(marker).sub(A::ONE.sub(phase_after))));
        residues.push(
            ordinary_gate.mul(
                A::ONE
                    .sub(message)
                    .mul(byte_value)
                    .sub(A::from_base(F(128)).mul(marker)),
            ),
        );
        residues.push(length_gate.mul(message.add(marker)));
        residues.push(length_gate.mul(phase_after.sub(A::ONE)));
        phase_after = phase_after.add(marker);
        message_increment = message_increment.add(message);
        marker_increment = marker_increment.add(marker);
    }
    residues.push(
        input_word
            .mul(row_active)
            .mul(final_block)
            .mul(fixed[SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1])
            .mul(current[0]),
    );
    residues.push(
        input_word
            .mul(row_active)
            .mul(final_block)
            .mul(fixed[SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1])
            .mul(current[0].sub(message_count.mul(A::from_base(F(8))))),
    );
    residues.push(
        call_continue.mul(
            next_message_count
                .sub(message_count.add(input_word.mul(row_active).mul(message_increment))),
        ),
    );
    residues.push(call_continue.mul(
        next_padding_phase.sub(padding_phase.add(input_word.mul(row_active).mul(marker_increment))),
    ));
    residues.push(
        digest.mul(
            current[SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1].sub(
                active_blocks
                    .mul(A::from_base(F(u64::try_from(
                        SHA_WORD_CAPACITY_WORD_IDS_PER_BLOCK_V1,
                    )
                    .expect("SHA word-id stride fits u64"))))
                    .add(fixed[SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1]),
            ),
        ),
    );
    for lane in 0..SHA_WORD_COPY_LANES_V1 {
        residues.push(inactive_compute.mul(current_aux[LOCAL_PAIR_01 + lane].sub(A::ONE)));
        residues.push(inactive_compute.mul(current_aux[LOCAL_PAIR_23 + lane].sub(A::ONE)));
        residues.push(inactive_compute.mul(current_aux[LOCAL_PAIR_45 + lane].sub(A::ONE)));
        residues.push(inactive_compute.mul(current_aux[LOCAL_QUAD + lane].sub(A::ONE)));
        residues.push(inactive_compute.mul(
            current_aux[LOCAL_PRODUCT_AFTER + lane].sub(current_aux[LOCAL_PRODUCT_BEFORE + lane]),
        ));
    }
    let memory_continue = fixed[FIX_MEMORY_CONTINUE];
    residues.push(memory.mul(boolean_error(current[2])));
    residues.push(memory.mul(boolean_error(current[5])));
    residues.push(inactive_memory.mul(sorted_same_next));
    residues.push(
        memory
            .mul(A::ONE.sub(row_active))
            .mul(A::ONE.sub(call_last))
            .mul(next[SHA_WORD_CAPACITY_ROW_ACTIVE_V1]),
    );
    residues.push(
        memory
            .mul(row_active)
            .mul(A::ONE.sub(next_active))
            .mul(sorted_same_next),
    );
    let adjacent_active = memory_continue.mul(row_active).mul(next_active);
    residues.push(adjacent_active.mul(next[3].sub(current[3].add(A::ONE.sub(sorted_same_next)))));
    residues.push(
        adjacent_active
            .mul(sorted_same_next)
            .mul(next[4].sub(current[4])),
    );
    residues.push(adjacent_active.mul(sorted_same_next).mul(next[5]));
    residues.push(
        adjacent_active
            .mul(A::ONE.sub(sorted_same_next))
            .mul(next[5].sub(A::ONE)),
    );
    residues.push(fixed[FIX_MEMORY_FIRST_SEGMENT].mul(current[3]));
    residues.push(fixed[FIX_MEMORY_FIRST_SEGMENT].mul(current[5].sub(A::ONE)));
    for lane in 0..SHA_WORD_COPY_LANES_V1 {
        let challenge = challenges.memory.lanes[lane];
        let execution_factor = memory_factor_v1(current[0], current[1], current[2], challenge);
        let sorted_factor = memory_factor_v1(current[3], current[4], current[5], challenge);
        let gated_execution_factor = A::ONE.add(row_active.mul(execution_factor.sub(A::ONE)));
        let gated_sorted_factor = A::ONE.add(row_active.mul(sorted_factor.sub(A::ONE)));
        residues.push(
            memory.mul(
                current_aux[MEMORY_EXEC_AFTER + lane]
                    .sub(current_aux[MEMORY_EXEC_BEFORE + lane].mul(gated_execution_factor)),
            ),
        );
        residues.push(
            memory.mul(
                current_aux[MEMORY_SORT_AFTER + lane]
                    .sub(current_aux[MEMORY_SORT_BEFORE + lane].mul(gated_sorted_factor)),
            ),
        );
        residues.push(
            memory_continue.mul(
                next_aux[MEMORY_EXEC_BEFORE + lane].sub(current_aux[MEMORY_EXEC_AFTER + lane]),
            ),
        );
        residues.push(
            memory_continue.mul(
                next_aux[MEMORY_SORT_BEFORE + lane].sub(current_aux[MEMORY_SORT_AFTER + lane]),
            ),
        );
        residues.push(
            fixed[FIX_MEMORY_FIRST_SEGMENT].mul(current_aux[MEMORY_EXEC_BEFORE + lane].sub(A::ONE)),
        );
        residues.push(
            fixed[FIX_MEMORY_FIRST_SEGMENT].mul(current_aux[MEMORY_SORT_BEFORE + lane].sub(A::ONE)),
        );
        residues.push(call_last.mul(
            current_aux[MEMORY_EXEC_AFTER + lane].sub(current_aux[GLOBAL_LOCAL_PRODUCT_END + lane]),
        ));
        residues.push(call_last.mul(
            current_aux[MEMORY_SORT_AFTER + lane].sub(current_aux[GLOBAL_LOCAL_PRODUCT_END + lane]),
        ));
        residues.push(
            call_continue.mul(
                next_aux[GLOBAL_LOCAL_PRODUCT_END + lane]
                    .sub(current_aux[GLOBAL_LOCAL_PRODUCT_END + lane]),
            ),
        );
    }
    for column in SHA_WORD_MEMORY_PRODUCT_WIDTH_V1..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1 {
        residues.push(memory.mul(current_aux[column]));
    }
    for column in CONTINUATION_OFFSET..GLOBAL_LOCAL_PRODUCT_END {
        residues.push(current_aux[column]);
    }
    if residues.len() != SHA_WORD_CAPACITY_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    Ok(residues)
}
#[cfg(test)]
fn validate_sigma_row(
    row: &[F],
    rotate_first: u8,
    rotate_second: u8,
    third: SigmaThirdV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if row.iter().any(|bit| !is_boolean(*bit)) {
        return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
    }
    for bit in 0..32 {
        let first = row[(bit + usize::from(rotate_first)) % 32];
        let second = row[(bit + usize::from(rotate_second)) % 32];
        let third = match third {
            SigmaThirdV1::Rotate(distance) => row[(bit + usize::from(distance)) % 32],
            SigmaThirdV1::Shift(distance) => row
                .get(bit + usize::from(distance))
                .copied()
                .filter(|_| bit + usize::from(distance) < 32)
                .unwrap_or(F::ZERO),
        };
        if row[32 + bit] != xor_three(first, second, third) {
            return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_boolean_chunk(
    rows: &[Vec<F>],
    fixed_rows: &[ShaWordFixedRowV1],
    index: usize,
    addresses: [usize; 4],
    chunk: u8,
    majority: bool,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    let row = rows.get(index).ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
    let chunk = usize::from(chunk);
    if chunk >= 4 {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    ensure_zero_suffix(row, 40)?;
    for operand in 0..4 {
        let bits = &row[4 + operand * 8..4 + (operand + 1) * 8];
        if bits.iter().any(|bit| !is_boolean(*bit)) {
            return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
        }
        let contribution = bits
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (within, bit)| {
                sum.add(bit.mul(F(1_u64 << (chunk * 8 + within))))
            });
        if chunk == 0 {
            if row[36 + operand] != contribution {
                return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
            }
        } else {
            let previous = rows
                .get(index - 1)
                .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
            let previous_fixed = fixed_rows
                .get(index - 1)
                .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
            let expected_previous = if majority {
                ShaWordFixedRowV1::Majority {
                    addresses,
                    chunk: u8::try_from(chunk - 1)
                        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?,
                }
            } else {
                ShaWordFixedRowV1::Choose {
                    addresses,
                    chunk: u8::try_from(chunk - 1)
                        .map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?,
                }
            };
            if previous_fixed != &expected_previous
                || previous[operand] != row[operand]
                || row[36 + operand] != previous[36 + operand].add(contribution)
            {
                return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
            }
        }
        if chunk == 3 && row[36 + operand] != row[operand] {
            return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
        }
    }
    for within in 0..8 {
        let x = row[4 + within];
        let y = row[12 + within];
        let z = row[20 + within];
        let output = row[28 + within];
        let expected = if majority {
            let xy = x.mul(y);
            let xz = x.mul(z);
            let yz = y.mul(z);
            xy.add(xz).add(yz).sub(F(2).mul(xy.mul(z)))
        } else {
            x.mul(y).add(F::ONE.sub(x).mul(z))
        };
        if output != expected {
            return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_local_rows(base: &ZkX509ShaWordStarkBaseV1) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    for index in 0..base.local_rows {
        let row = base
            .base_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?;
        match base
            .fixed_rows
            .get(index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Topology)?
        {
            ShaWordFixedRowV1::Word {
                fixed_bits,
                address: _,
            } => {
                ensure_zero_suffix(row, 33)?;
                validate_range_row(row[0], &row[1..33])?;
                for (actual, expected) in row[1..33].iter().zip(fixed_bits) {
                    match *expected {
                        -1 => {}
                        0 if *actual == F::ZERO => {}
                        1 if *actual == F::ONE => {}
                        _ => return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint),
                    }
                }
            }
            ShaWordFixedRowV1::Sigma {
                rotate_first,
                rotate_second,
                third,
                ..
            } => validate_sigma_row(row, *rotate_first, *rotate_second, *third)?,
            ShaWordFixedRowV1::Choose { addresses, chunk } => validate_boolean_chunk(
                &base.base_rows,
                &base.fixed_rows,
                index,
                *addresses,
                *chunk,
                false,
            )?,
            ShaWordFixedRowV1::Majority { addresses, chunk } => validate_boolean_chunk(
                &base.base_rows,
                &base.fixed_rows,
                index,
                *addresses,
                *chunk,
                true,
            )?,
            ShaWordFixedRowV1::Add {
                arity, constant, ..
            } => {
                let arity = usize::from(*arity);
                if !(1..=5).contains(&arity) {
                    return Err(ZkX509ShaWordStarkErrorV1::Topology);
                }
                ensure_zero_suffix(row, 41)?;
                if row[arity..5].iter().any(|value| *value != F::ZERO)
                    || row[6..9].iter().any(|bit| !is_boolean(*bit))
                {
                    return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
                }
                validate_range_row(row[5], &row[9..41])?;
                let carry = row[6].add(F(2).mul(row[7])).add(F(4).mul(row[8]));
                let sum = row[..arity]
                    .iter()
                    .copied()
                    .fold(F(u64::from(*constant)), F::add);
                if sum != row[5].add(F(1_u64 << 32).mul(carry)) {
                    return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
                }
            }
            ShaWordFixedRowV1::Digest { expected, .. } => {
                ensure_zero_suffix(row, 33)?;
                validate_range_row(row[0], &row[1..33])?;
                if row[0] != F(u64::from(*expected)) {
                    return Err(ZkX509ShaWordStarkErrorV1::LocalConstraint);
                }
            }
            ShaWordFixedRowV1::Memory { .. } | ShaWordFixedRowV1::Padding => {
                return Err(ZkX509ShaWordStarkErrorV1::Topology);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
fn local_events_for_row(
    fixed: &ShaWordFixedRowV1,
    row: &[F],
) -> Result<Vec<WordMemoryAccessV1>, ZkX509ShaWordStarkErrorV1> {
    match fixed {
        ShaWordFixedRowV1::Word { address, .. } => Ok(vec![write(WordIdV1(*address), row[0])?]),
        ShaWordFixedRowV1::Sigma { input, output, .. } => Ok(vec![
            read(WordIdV1(*input), pack_bits(&row[..32]))?,
            write(WordIdV1(*output), pack_bits(&row[32..64]))?,
        ]),
        ShaWordFixedRowV1::Choose { addresses, chunk }
        | ShaWordFixedRowV1::Majority { addresses, chunk } => {
            if *chunk == 0 {
                Ok(vec![
                    read(WordIdV1(addresses[0]), row[0])?,
                    read(WordIdV1(addresses[1]), row[1])?,
                    read(WordIdV1(addresses[2]), row[2])?,
                    write(WordIdV1(addresses[3]), row[3])?,
                ])
            } else {
                Ok(Vec::new())
            }
        }
        ShaWordFixedRowV1::Add {
            inputs,
            arity,
            output,
            ..
        } => {
            let arity = usize::from(*arity);
            if !(1..=5).contains(&arity) {
                return Err(ZkX509ShaWordStarkErrorV1::Topology);
            }
            let mut events = Vec::with_capacity(arity + 1);
            for index in 0..arity {
                events.push(read(WordIdV1(inputs[index]), row[index])?);
            }
            events.push(write(WordIdV1(*output), row[5])?);
            Ok(events)
        }
        ShaWordFixedRowV1::Digest { address, .. } => Ok(vec![read(WordIdV1(*address), row[0])?]),
        ShaWordFixedRowV1::Memory { .. } | ShaWordFixedRowV1::Padding => Ok(Vec::new()),
    }
}
#[cfg(test)]
fn validate_base_topology_and_memory(
    base: &ZkX509ShaWordStarkBaseV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if base.statement.message_len > ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 {
        return Err(ZkX509ShaWordStarkErrorV1::Resource);
    }
    ensure_canonical_fields(&base.base_rows, SHA_WORD_BASE_WIDTH_V1)?;
    let expected = expected_fixed_topology(base.statement)?;
    if base.fixed_rows != expected.fixed_rows
        || base.local_rows != expected.local_rows
        || base.segment_rows != expected.segment_rows
        || base.active_rows_per_segment != expected.active_rows_per_segment
        || base.base_rows.len() != expected.base_rows.len()
        || base.execution.len() != expected.execution.len()
        || base.sorted.len() != expected.sorted.len()
        || base.local_events.len() != base.local_rows
    {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    validate_local_rows(base)?;
    let mut derived_execution = Vec::new();
    for index in 0..base.local_rows {
        let expected_events =
            local_events_for_row(&base.fixed_rows[index], &base.base_rows[index])?;
        if base.local_events[index] != expected_events {
            return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
        }
        derived_execution.extend(expected_events);
    }
    if derived_execution != base.execution {
        return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
    }
    for memory_index in 0..base.execution.len() {
        let global_index = base
            .local_rows
            .checked_add(memory_index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
        let row = &base.base_rows[global_index];
        ensure_zero_suffix(row, 6)?;
        let fixed = match &base.fixed_rows[global_index] {
            ShaWordFixedRowV1::Memory {
                execution_address,
                execution_write,
                sorted_address,
                sorted_write,
                sorted_same_address_next,
                memory_first,
                memory_last,
            } => (
                *execution_address,
                *execution_write,
                *sorted_address,
                *sorted_write,
                *sorted_same_address_next,
                *memory_first,
                *memory_last,
            ),
            _ => return Err(ZkX509ShaWordStarkErrorV1::Topology),
        };
        let execution = WordMemoryAccessV1 {
            address: row[0],
            value: row[1],
            is_write: row[2],
        };
        let sorted = WordMemoryAccessV1 {
            address: row[3],
            value: row[4],
            is_write: row[5],
        };
        if !is_boolean(execution.is_write)
            || !is_boolean(sorted.is_write)
            || execution.address
                != F(u64::try_from(fixed.0).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?)
            || execution.is_write != F(u64::from(fixed.1))
            || sorted.address
                != F(u64::try_from(fixed.2).map_err(|_| ZkX509ShaWordStarkErrorV1::Resource)?)
            || sorted.is_write != F(u64::from(fixed.3))
            || fixed.5 != (memory_index == 0)
            || fixed.6 != (memory_index + 1 == base.execution.len())
            || execution != base.execution[memory_index]
            || sorted != base.sorted[memory_index]
        {
            return Err(ZkX509ShaWordStarkErrorV1::Memory);
        }
        if fixed.4 {
            let next = base
                .sorted
                .get(memory_index + 1)
                .ok_or(ZkX509ShaWordStarkErrorV1::Memory)?;
            if next.address != sorted.address
                || next.value != sorted.value
                || next.is_write != F::ZERO
            {
                return Err(ZkX509ShaWordStarkErrorV1::Memory);
            }
        } else if !fixed.6 {
            let next = base
                .sorted
                .get(memory_index + 1)
                .ok_or(ZkX509ShaWordStarkErrorV1::Memory)?;
            if next.address != sorted.address.add(F::ONE) || next.is_write != F::ONE {
                return Err(ZkX509ShaWordStarkErrorV1::Memory);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_continuation_sequence(
    trace: &ZkX509ShaWordStarkTraceV1,
    expected: &[ShaWordPhysicalContinuationV1],
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    if trace.continuations != expected {
        return Err(ZkX509ShaWordStarkErrorV1::Continuation);
    }
    let first = expected
        .first()
        .ok_or(ZkX509ShaWordStarkErrorV1::Continuation)?;
    if first.segment_index != 0
        || first.global_row_start != 0
        || first.local_row_start != 0
        || first.memory_row_start != 0
        || first.execution_product_start != [F::ONE; SHA_WORD_COPY_LANES_V1]
        || first.sorted_product_start != [F::ONE; SHA_WORD_COPY_LANES_V1]
    {
        return Err(ZkX509ShaWordStarkErrorV1::Continuation);
    }
    for pair in expected.windows(2) {
        if pair[1].segment_index != pair[0].segment_index + 1
            || pair[1].global_row_start != pair[0].global_row_end
            || pair[1].local_row_start != pair[0].local_row_end
            || pair[1].memory_row_start != pair[0].memory_row_end
            || pair[1].execution_product_start != pair[0].execution_product_end
            || pair[1].sorted_product_start != pair[0].sorted_product_end
        {
            return Err(ZkX509ShaWordStarkErrorV1::Continuation);
        }
    }
    let last = expected
        .last()
        .ok_or(ZkX509ShaWordStarkErrorV1::Continuation)?;
    if last.global_row_end != trace.base.base_rows.len()
        || last.local_row_end != trace.base.local_rows
        || last.memory_row_end != trace.base.execution.len()
        || last.execution_product_end != last.sorted_product_end
    {
        return Err(ZkX509ShaWordStarkErrorV1::Continuation);
    }
    Ok(())
}
/// Validate the exact base-domain SHA-word relation, including all redundant
/// witness material. No event list, fixed row, memory table, product, or
/// continuation supplied by the prover is accepted without derivation.
#[cfg(test)]
pub fn validate_sha_word_stark_trace_v1(
    trace: &ZkX509ShaWordStarkTraceV1,
    challenges: ZkX509WordMemoryChallengesV1,
) -> Result<(), ZkX509ShaWordStarkErrorV1> {
    validate_challenges(challenges)?;
    validate_base_topology_and_memory(&trace.base)?;
    ensure_canonical_fields(&trace.aux_rows, SHA_WORD_AUX_WIDTH_V1)?;
    if trace.aux_rows.len() != trace.base.base_rows.len() {
        return Err(ZkX509ShaWordStarkErrorV1::Topology);
    }
    let mut local_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
    for index in 0..trace.base.local_rows {
        let (expected, after) =
            local_product_row(&trace.base.local_events[index], local_product, challenges)?;
        if trace.aux_rows[index][..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1] != expected {
            return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
        }
        local_product = after;
    }
    let mut memory_products = Vec::with_capacity(trace.base.execution.len());
    let mut execution_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
    let mut sorted_product = [F::ONE; SHA_WORD_COPY_LANES_V1];
    for (memory_index, (execution, sorted)) in trace
        .base
        .execution
        .iter()
        .copied()
        .zip(trace.base.sorted.iter().copied())
        .enumerate()
    {
        let mut expected = [F::ZERO; SHA_WORD_MEMORY_PRODUCT_WIDTH_V1];
        expected[MEMORY_EXEC_BEFORE..MEMORY_EXEC_BEFORE + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&execution_product);
        expected[MEMORY_SORT_BEFORE..MEMORY_SORT_BEFORE + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&sorted_product);
        for lane in 0..SHA_WORD_COPY_LANES_V1 {
            execution_product[lane] =
                execution_product[lane].mul(compress_access(execution, challenges.lanes[lane]));
            sorted_product[lane] =
                sorted_product[lane].mul(compress_access(sorted, challenges.lanes[lane]));
        }
        expected[MEMORY_EXEC_AFTER..MEMORY_EXEC_AFTER + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&execution_product);
        expected[MEMORY_SORT_AFTER..MEMORY_SORT_AFTER + SHA_WORD_COPY_LANES_V1]
            .copy_from_slice(&sorted_product);
        let global_index = trace
            .base
            .local_rows
            .checked_add(memory_index)
            .ok_or(ZkX509ShaWordStarkErrorV1::Resource)?;
        if trace.aux_rows[global_index][..SHA_WORD_MEMORY_PRODUCT_WIDTH_V1] != expected
            || trace.aux_rows[global_index]
                [SHA_WORD_MEMORY_PRODUCT_WIDTH_V1..SHA_WORD_LOCAL_PRODUCT_WIDTH_V1]
                .iter()
                .any(|value| *value != F::ZERO)
        {
            return Err(ZkX509ShaWordStarkErrorV1::Memory);
        }
        memory_products.push(expected);
    }
    if execution_product != sorted_product || local_product != execution_product {
        return Err(ZkX509ShaWordStarkErrorV1::LocalCopy);
    }
    let expected_continuations = build_continuations(&trace.base, &memory_products)?;
    validate_continuation_sequence(trace, &expected_continuations)?;
    for (index, row) in trace.aux_rows.iter().enumerate() {
        let segment = (index / trace.base.segment_rows).min(expected_continuations.len() - 1);
        let mut expected_tail = vec![F::ZERO; SHA_WORD_AUX_WIDTH_V1];
        write_continuation(
            &mut expected_tail,
            expected_continuations[segment],
            local_product,
        )?;
        if row[CONTINUATION_OFFSET..] != expected_tail[CONTINUATION_OFFSET..] {
            return Err(ZkX509ShaWordStarkErrorV1::Continuation);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn word_event_sort_ties_are_identical_and_in_place_order_matches_reference() {
        for message in [b"abc".to_vec(), (0_u8..97).collect::<Vec<_>>()] {
            let circuit = build_sha256_word_circuit_v1(&message).unwrap();
            let raw = build_sha_word_stark_base_v1(
                ZkX509ShaWordStarkStatementV1 {
                    message_len: message.len(),
                    digest: circuit.digest(),
                },
                &message,
            )
            .unwrap();
            let key =
                |event: &WordMemoryAccessV1| (event.address.0, u8::from(event.is_write != F::ONE));
            let mut reference = raw.execution.clone();
            reference.sort_by_key(key);
            let mut ties = 0;
            for pair in reference.windows(2) {
                if key(&pair[0]) == key(&pair[1]) {
                    ties += 1;
                    assert_eq!(pair[0], pair[1]);
                }
            }
            assert!(ties > 0);
            assert_eq!(raw.sorted, reference);
            assert_eq!(raw.sorted, circuit.stark_memory_v1().sorted);
        }
    }

    #[test]
    fn failed_sha_memory_binding_erases_populated_auxiliary_table() {
        use super::super::private_table::inspection::observe_v1;

        let mut base = build_sha_word_capacity_base_source_v1(b"abc", 63, false).unwrap();
        let expected_cells = base.logical_rows() * SHA_WORD_CAPACITY_AUX_WIDTH_V1;
        // This corrupts the late permutation equality after the entire private
        // auxiliary table has been filled, rather than failing at admission.
        base.execution[0].value = base.execution[0].value.add(F::ONE);
        let (result, erasures) = observe_v1(|| base.bind_memory_challenges_v1(challenges()));
        assert!(matches!(result, Err(ZkX509ShaWordStarkErrorV1::LocalCopy)));
        assert!(erasures.iter().any(|erasure| {
            erasure.cells == expected_cells
                && erasure.nonzero_before > 0
                && erasure.nonzero_after == 0
        }));
    }

    #[test]
    fn retained_sha_source_erasure_clears_live_cells_and_preserves_public_fixed_rows() {
        let clean_events = |events: &[WordMemoryAccessV1]| {
            events.iter().all(|event| {
                event.address == F::ZERO && event.value == F::ZERO && event.is_write == F::ZERO
            })
        };
        let mut raw = fixture().base.clone();
        assert_eq!(
            format!("{raw:?}"),
            "ZkX509ShaWordStarkBaseV1 { <private material redacted> }"
        );
        let raw_rows = raw.base_rows.len();
        raw.zeroize_private_cells_v1();
        assert_eq!(raw.base_rows.len(), raw_rows);
        assert!(
            raw.base_rows
                .iter()
                .flatten()
                .all(|value| *value == F::ZERO)
        );
        assert!(raw.local_events.iter().all(|events| clean_events(events)));
        assert!(clean_events(&raw.execution) && clean_events(&raw.sorted));
        assert!(raw.fixed_rows.iter().all(|fixed| match fixed {
            ShaWordFixedRowV1::Digest { expected, .. } => *expected == 0,
            _ => true,
        }));
        let mut base = build_sha_word_capacity_base_source_v1(b"abc", 63, false).unwrap();
        let fixed = base.fixed_rows.clone();
        let base_rows = base.base_rows.len();
        base.zeroize_private_cells_v1();
        assert_eq!(base.base_rows.len(), base_rows);
        assert!(
            base.base_rows
                .iter()
                .flatten()
                .all(|value| *value == F::ZERO)
        );
        assert!(base.local_events.iter().all(|events| clean_events(events)));
        assert!(clean_events(&base.execution) && clean_events(&base.sorted));
        assert_eq!(base.fixed_rows, fixed);
        assert_eq!(
            (
                base.message_len,
                base.active_blocks,
                base.actual_compute_rows
            ),
            (0, 0, 0)
        );
        let mut bound = build_sha_word_capacity_trace_v1(b"abc", 63, false, challenges()).unwrap();
        let fixed = bound.fixed_rows.clone();
        let bound_rows = bound.aux_rows.len();
        bound.zeroize_private_cells_v1();
        assert_eq!(bound.aux_rows.len(), bound_rows);
        assert!(
            bound
                .base_rows
                .iter()
                .flatten()
                .all(|value| *value == F::ZERO)
        );
        assert!(
            bound
                .aux_rows
                .iter()
                .flatten()
                .all(|value| *value == F::ZERO)
        );
        assert_eq!(bound.fixed_rows, fixed);
        assert_eq!((bound.message_len, bound.active_blocks), (0, 0));
    }

    #[test]
    fn maximum_manifest_source_scratch_forecast_fits_declared_gibibyte() {
        use super::super::{
            air::U32RangeAirRowV1,
            sha_call_bus_stark::{ZkX509ShaCallPublicShapeV1, ZkX509ShaCallScheduleV1},
        };
        use core::mem::size_of;
        let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 4,
        })
        .unwrap();
        let maximum = schedule
            .calls()
            .iter()
            .max_by_key(|call| call.maximum_logical_rows())
            .unwrap();
        // The framed CRL commitment is larger than the unframed TBS calls.
        assert_eq!(maximum.maximum_blocks, 66);
        let local = maximum.maximum_local_rows;
        let memory = maximum.maximum_memory_rows;
        let rows = maximum.maximum_logical_rows();
        assert_eq!((local, memory, rows), (70_240, 140_992, 211_232));
        // Upper capacity forecasts for the current Vec builders. These are allocation
        // policy regression bounds, not allocator metadata or measured process RSS.
        // Every operation/word has at least one local row; six complete circuit
        // copies overcharge the canonical validation and actual/shape compiler overlap.
        let circuit = local.next_power_of_two()
            * (size_of::<U32RangeAirRowV1>() + size_of::<WordOperationV1>())
            + (maximum.maximum_blocks * 16).next_power_of_two() * size_of::<WordIdV1>()
            + 2 * memory.next_power_of_two() * size_of::<WordMemoryAccessV1>();
        let event_heap = 6 * local * size_of::<WordMemoryAccessV1>();
        let memory_tables = 2 * memory.next_power_of_two() * size_of::<WordMemoryAccessV1>();
        let raw = rows * SHA_WORD_BASE_WIDTH_V1 * size_of::<F>()
            + rows.next_power_of_two() * (2 * size_of::<Vec<F>>() + size_of::<ShaWordFixedRowV1>())
            + event_heap
            + memory_tables;
        // The bound call retains 24 call/RFC products in addition to the word
        // base/fixed/aux matrices. Conservatively keep raw material and all circuit
        // copies live while charging these final matrices, although their scopes end.
        let bound = rows
            * (SHA_WORD_CAPACITY_BASE_WIDTH_V1
                + SHA_WORD_CAPACITY_FIXED_WIDTH_V1
                + SHA_WORD_CAPACITY_AUX_WIDTH_V1
                + 24)
            * size_of::<F>()
            + rows.next_power_of_two() * size_of::<Vec<WordMemoryAccessV1>>()
            + event_heap
            + memory_tables;
        // Includes fixed-schedule rows, sort scratch, small word-index containers,
        // native output and raw circuit headers beyond the charged arrays.
        let forecast = 6 * circuit + raw + bound + (32 << 20);
        let production = source_replay_scratch_forecast_v1(maximum.maximum_blocks).unwrap();
        assert!(production <= forecast);
        assert!(
            forecast < super::super::allocation_payload::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1,
            "SHA replay scratch forecast {forecast}"
        );
        assert!(source_replay_scratch_forecast_v1(0).is_err());
        assert!(source_replay_scratch_forecast_v1(usize::MAX).is_err());
        eprintln!("maximum SHA replay scratch payload forecast: {forecast}");
    }

    #[test]
    fn immutable_input_index_capacity_and_lookup_match_independent_map() {
        use super::super::allocation_payload::vector_v1;
        for length in [0, 1, 64, 129] {
            let mut schedule = compile_sha_word_capacity_fixed_schedule_v1(length, true).unwrap();
            let circuit = build_sha256_word_circuit_v1(&vec![0; length]).unwrap();
            let independent: BTreeMap<_, _> = circuit
                .stark_input_words_v1()
                .iter()
                .enumerate()
                .map(|(index, word)| (word.0, index))
                .collect();
            assert_eq!(
                schedule.input_word_indices,
                independent
                    .iter()
                    .map(|(address, index)| (*address, *index))
                    .collect::<Vec<_>>()
            );
            for (address, expected) in independent {
                let position = schedule
                    .input_word_indices
                    .binary_search_by_key(&address, |entry| entry.0)
                    .unwrap();
                assert_eq!(schedule.input_word_indices[position].1, expected);
            }
            let before = schedule.allocated_heap_bytes_v1();
            let old = vector_v1(&schedule.input_word_indices);
            schedule.input_word_indices.reserve_exact(17);
            assert_eq!(
                schedule.allocated_heap_bytes_v1(),
                before - old + vector_v1(&schedule.input_word_indices)
            );
        }
    }

    use super::*;
    use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
    use crate::privacy_engines::zk_x509::sha256_word_air::sha256_word_total_rows_for_message_len_v1;
    use std::sync::OnceLock;
    fn challenges() -> ZkX509WordMemoryChallengesV1 {
        ZkX509WordMemoryChallengesV1 {
            lanes: [
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(3),
                    address: F(5),
                    value: F(7),
                    is_write: F(11),
                },
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(13),
                    address: F(17),
                    value: F(19),
                    is_write: F(23),
                },
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(29),
                    address: F(31),
                    value: F(37),
                    is_write: F(41),
                },
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(43),
                    address: F(47),
                    value: F(53),
                    is_write: F(59),
                },
            ],
        }
    }
    fn stark_challenges() -> ZkX509ShaWordStarkChallengesV1 {
        ZkX509ShaWordStarkChallengesV1 {
            memory: challenges(),
            base_folding: [F(61), F(67), F(71), F(73)],
        }
    }
    fn build_trace(message: &[u8]) -> ZkX509ShaWordStarkTraceV1 {
        let circuit = build_sha256_word_circuit_v1(message).expect("valid SHA word circuit");
        let statement = ZkX509ShaWordStarkStatementV1 {
            message_len: message.len(),
            digest: circuit.digest(),
        };
        let base = build_sha_word_stark_base_v1(statement, message).expect("valid SHA base trace");
        build_sha_word_stark_trace_v1(base, challenges()).expect("valid SHA auxiliary trace")
    }
    fn fixture() -> &'static ZkX509ShaWordStarkTraceV1 {
        static FIXTURE: OnceLock<ZkX509ShaWordStarkTraceV1> = OnceLock::new();
        FIXTURE.get_or_init(|| build_trace(b"abc"))
    }
    fn mutate(value: &mut F) {
        *value = value.add(F::ONE);
    }
    #[test]
    fn canonical_empty_single_and_multi_block_traces_validate() {
        for message in [Vec::new(), b"abc".to_vec(), (0_u8..80).collect::<Vec<_>>()] {
            let trace = build_trace(&message);
            validate_sha_word_stark_trace_v1(&trace, challenges()).expect("canonical trace");
            assert_eq!(trace.base.statement.message_len, message.len());
            assert_eq!(
                trace.base.base_rows.len(),
                trace.base.local_rows + trace.base.execution.len()
            );
            assert_eq!(trace.aux_rows.len(), trace.base.base_rows.len());
        }
    }
    #[test]
    fn complete_word_challenges_are_commitment_bound_and_domain_separated() {
        let profile = PrivacyOuterDigestV1::from_bytes([0x11; 48]);
        let public = PrivacyOuterDigestV1::from_bytes([0x22; 48]);
        let root = PrivacyOuterDigestV1::from_bytes([0x33; 48]);
        let sample = |root: PrivacyOuterDigestV1| {
            let root = root.to_bytes();
            let mut transcript = TransparentTranscriptV1::new(
                super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
                b"zk-x509-sha-word-test",
                &profile,
                &public,
            )
            .expect("transcript");
            transcript
                .absorb(b"zk-x509-sha-word-base-root-v1", &[&root])
                .expect("root");
            derive_zk_x509_sha_word_stark_challenges_v1(&mut transcript).expect("challenges")
        };
        let challenges = sample(root);
        validate_zk_x509_sha_word_stark_challenges_v1(challenges).expect("valid challenges");
        assert_eq!(challenges, sample(root));
        let mut changed_words = root.to_bytes();
        changed_words[0] ^= 1;
        let changed_root = PrivacyOuterDigestV1::from_bytes(changed_words);
        assert_ne!(challenges, sample(changed_root));
        assert!(
            challenges
                .base_folding
                .iter()
                .all(|folding| *folding != F::ZERO)
        );
        assert!(
            challenges
                .base_folding
                .iter()
                .enumerate()
                .all(|(index, folding)| !challenges.base_folding[..index].contains(folding))
        );
        assert!(challenges.memory.lanes.iter().all(|memory| {
            !challenges.base_folding.contains(&memory.beta)
                && !challenges.base_folding.contains(&memory.address)
                && !challenges.base_folding.contains(&memory.value)
                && !challenges.base_folding.contains(&memory.is_write)
        }));
    }
    fn capacity_row_residues(trace: &ZkX509ShaWordCapacityTraceV1, index: usize) -> Vec<F> {
        let next = if index + 1 < trace.logical_rows() {
            index + 1
        } else {
            index
        };
        evaluate_zk_x509_sha_word_capacity_residues_v1(
            trace.base_row(index).expect("base"),
            trace.base_row(next).expect("next base"),
            trace.aux_row(index).expect("aux"),
            trace.aux_row(next).expect("next aux"),
            trace.fixed_row(index).expect("fixed"),
            stark_challenges(),
        )
        .expect("capacity residues")
    }
    #[test]
    fn verifier_capacity_fixed_schedule_exactly_replays_trace_fixed_rows() {
        for (message, maximum, exact) in [
            (b"abc".as_slice(), 127_usize, false),
            (&[0x5a; 63][..], 63, true),
        ] {
            let schedule =
                compile_sha_word_capacity_fixed_schedule_v1(maximum, exact).expect("fixed");
            let trace = build_sha_word_capacity_trace_v1(message, maximum, exact, challenges())
                .expect("capacity");
            assert_eq!(schedule.maximum_message_len(), maximum);
            assert_eq!(schedule.exact_length(), exact);
            assert_eq!(schedule.maximum_blocks(), trace.maximum_blocks);
            assert_eq!(schedule.maximum_local_rows(), trace.maximum_local_rows);
            assert_eq!(schedule.maximum_memory_rows(), trace.maximum_memory_rows);
            assert_eq!(schedule.logical_rows(), trace.logical_rows());
            for index in 0..trace.logical_rows() {
                assert_eq!(
                    schedule.fixed_row_v1(index).expect("verifier fixed row"),
                    *trace.fixed_row(index).expect("trace fixed row"),
                    "fixed row {index}"
                );
            }
            assert_eq!(
                schedule.fixed_row_v1(schedule.logical_rows()),
                Err(ZkX509ShaWordStarkErrorV1::Resource)
            );
        }
        assert!(matches!(
            compile_sha_word_capacity_fixed_schedule_v1(
                ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 + 1,
                false
            ),
            Err(ZkX509ShaWordStarkErrorV1::Resource)
        ));
    }
    #[test]
    fn reduced_preprocessed_fixed_rows_reconstruct_exactly_and_reject_bad_native_identities() {
        for (maximum, exact) in [(0_usize, true), (127, false), (4_096, false)] {
            let schedule =
                compile_sha_word_capacity_fixed_schedule_v1(maximum, exact).expect("fixed");
            for index in 0..schedule.logical_rows() {
                let full = schedule.fixed_row_v1(index).expect("fixed row");
                let reduced =
                    reduce_zk_x509_sha_word_fixed_row_v1(&full).expect("canonical identities");
                assert_eq!(
                    expand_zk_x509_sha_word_fixed_row_v1(&reduced),
                    full,
                    "maximum {maximum}, row {index}"
                );
                if index == 0 {
                    for omitted in ZK_X509_SHA_WORD_PREPROCESSED_OMITTED_COLUMNS_V1 {
                        let mut corrupted = full;
                        corrupted[omitted] = corrupted[omitted].add(F::ONE);
                        assert_eq!(
                            reduce_zk_x509_sha_word_fixed_row_v1(&corrupted),
                            Err(ZkX509ShaWordStarkErrorV1::Topology),
                            "omitted source column {omitted} must be derived, not trusted"
                        );
                    }
                }
            }
        }
        let mut arbitrary = [F::ZERO; ZK_X509_SHA_WORD_PREPROCESSED_FIXED_WIDTH_V1];
        for (index, value) in arbitrary.iter_mut().enumerate() {
            *value = F(u64::try_from(index + 1).expect("small test index"));
        }
        let expanded = expand_zk_x509_sha_word_fixed_row_v1(&arbitrary);
        assert_eq!(
            reduce_zk_x509_sha_word_fixed_row_v1(&expanded).expect("linear LDE identities"),
            arbitrary
        );
    }
    #[test]
    fn fixed_capacity_private_lengths_and_padding_boundaries_validate() {
        for length in [0_usize, 1, 55, 56, 63, 64, 65, 127] {
            let message = (0..length)
                .map(|index| u8::try_from(index % 251).expect("byte"))
                .collect::<Vec<_>>();
            let trace = build_sha_word_capacity_trace_v1(&message, 127, false, challenges())
                .expect("capacity");
            assert_eq!(trace.message_len, length);
            assert_eq!(trace.maximum_message_len, 127);
            assert_eq!(trace.maximum_blocks, 3);
            assert_eq!(
                trace.base_rows.len(),
                trace.maximum_local_rows + trace.maximum_memory_rows
            );
            assert_eq!(trace.aux_rows.len(), trace.base_rows.len());
            assert_eq!(trace.fixed_rows.len(), trace.base_rows.len());
            for index in 0..trace.logical_rows() {
                let residues = capacity_row_residues(&trace, index);
                assert_eq!(residues.len(), SHA_WORD_CAPACITY_CONSTRAINT_COUNT_V1);
                assert!(
                    residues.iter().all(|residue| *residue == F::ZERO),
                    "nonzero capacity residue for length {length} at row {index}"
                );
            }
        }
    }
    #[test]
    fn fixed_capacity_stride_matches_the_rows_emitted_by_the_stark_builder() {
        for (length, blocks) in [(0_usize, 1_usize), (64, 2), (313, 6)] {
            let message = vec![0x5a; length];
            let circuit = build_sha256_word_circuit_v1(&message).expect("word circuit");
            let statement = ZkX509ShaWordStarkStatementV1 {
                message_len: length,
                digest: circuit.digest(),
            };
            let base = build_sha_word_stark_base_v1(statement, &message).expect("STARK base");
            assert_eq!(
                base.local_rows,
                SHA_WORD_CAPACITY_LOCAL_INITIAL_ROWS_PER_CALL_V1
                    + blocks * SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1
                    + SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1,
                "length {length}"
            );
            assert_eq!(
                base.execution.len(),
                blocks * SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1
                    + SHA_WORD_CAPACITY_MEMORY_ROWS_PER_CALL_V1,
                "length {length}"
            );
        }
    }
    #[test]
    fn padding_marker_can_precede_the_unique_final_length_block() {
        for length in 56_usize..=63 {
            let trace =
                build_sha_word_capacity_trace_v1(&vec![0x5a; length], 127, false, challenges())
                    .expect("two-block padding");
            assert_eq!(trace.active_blocks, 2);
            let marker_row = trace
                .base_rows
                .iter()
                .position(|row| {
                    row[SHA_WORD_CAPACITY_MARKER_MASK_V1..SHA_WORD_CAPACITY_MARKER_MASK_V1 + 4]
                        .contains(&F::ONE)
                })
                .expect("padding marker");
            assert_eq!(
                trace.base_rows[marker_row][SHA_WORD_CAPACITY_FINAL_BLOCK_V1],
                F::ZERO,
                "length {length} marker belongs to the penultimate block"
            );
            assert!(
                capacity_row_residues(&trace, marker_row)
                    .iter()
                    .all(|residue| *residue == F::ZERO)
            );
        }
    }
    #[test]
    fn fixed_capacity_rejects_cap_and_padding_selector_mutations() {
        assert!(matches!(
            build_sha_word_capacity_trace_v1(&[0_u8; 128], 127, false, challenges()),
            Err(ZkX509ShaWordStarkErrorV1::Resource)
        ));
        let mut trace =
            build_sha_word_capacity_trace_v1(b"abc", 127, false, challenges()).expect("capacity");
        let marker_row = trace
            .base_rows
            .iter()
            .position(|row| {
                row[SHA_WORD_CAPACITY_MARKER_MASK_V1..SHA_WORD_CAPACITY_MARKER_MASK_V1 + 4]
                    .contains(&F::ONE)
            })
            .expect("marker row");
        trace.base_rows[marker_row][SHA_WORD_CAPACITY_MARKER_MASK_V1] =
            trace.base_rows[marker_row][SHA_WORD_CAPACITY_MARKER_MASK_V1].add(F::ONE);
        assert!(
            capacity_row_residues(&trace, marker_row)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut trace =
            build_sha_word_capacity_trace_v1(b"abc", 127, false, challenges()).expect("capacity");
        let inactive_row = trace.base_rows[..trace.maximum_local_rows]
            .iter()
            .position(|row| row[SHA_WORD_CAPACITY_ROW_ACTIVE_V1] == F::ZERO)
            .expect("first inactive local row");
        assert_eq!(
            trace.base_rows[inactive_row][SHA_WORD_CAPACITY_ROW_ACTIVE_V1],
            F::ZERO
        );
        trace.base_rows[inactive_row][0] = F::ONE;
        assert!(
            capacity_row_residues(&trace, inactive_row)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut trace =
            build_sha_word_capacity_trace_v1(b"abc", 127, false, challenges()).expect("capacity");
        let digest_row = trace.maximum_local_rows - SHA_WORD_CAPACITY_LOCAL_ROWS_PER_CALL_V1;
        trace.base_rows[digest_row][SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1] =
            trace.base_rows[digest_row][SHA_WORD_CAPACITY_DYNAMIC_ADDRESS_V1].add(F::ONE);
        assert!(
            capacity_row_residues(&trace, digest_row)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut trace =
            build_sha_word_capacity_trace_v1(b"abc", 127, false, challenges()).expect("capacity");
        let disallowed_message_row = trace
            .fixed_rows
            .iter()
            .position(|fixed| {
                fixed[SHA_WORD_CAPACITY_INPUT_WORD_V1] == F::ONE
                    && fixed[SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1] == F(31)
            })
            .expect("last maximum-capacity input word");
        assert_eq!(
            trace.fixed_rows[disallowed_message_row][SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1 + 3],
            F::ZERO
        );
        trace.base_rows[disallowed_message_row][SHA_WORD_CAPACITY_MESSAGE_MASK_V1 + 3] = F::ONE;
        assert!(
            capacity_row_residues(&trace, disallowed_message_row)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut trace =
            build_sha_word_capacity_trace_v1(b"abc", 127, false, challenges()).expect("capacity");
        let inactive_input_row = trace
            .fixed_rows
            .iter()
            .position(|fixed| {
                fixed[SHA_WORD_CAPACITY_INPUT_WORD_V1] == F::ONE
                    && fixed[SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1] == F(16)
            })
            .expect("first inactive-block input word");
        assert_eq!(
            trace.fixed_rows[inactive_input_row][SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1],
            F::ONE
        );
        assert_eq!(
            trace.base_rows[inactive_input_row][SHA_WORD_CAPACITY_ROW_ACTIVE_V1],
            F::ZERO
        );
        trace.base_rows[inactive_input_row][SHA_WORD_CAPACITY_MARKER_MASK_V1] = F::ONE;
        assert!(
            capacity_row_residues(&trace, inactive_input_row)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut trace =
            build_sha_word_capacity_trace_v1(b"abc", 127, false, challenges()).expect("capacity");
        let inactive_memory_row =
            trace.maximum_local_rows + capacity_memory_rows_v1(trace.active_blocks).expect("rows");
        assert_eq!(
            trace.base_rows[inactive_memory_row][SHA_WORD_CAPACITY_ROW_ACTIVE_V1],
            F::ZERO
        );
        trace.base_rows[inactive_memory_row][SHA_WORD_CAPACITY_SORTED_SAME_NEXT_V1] = F::ONE;
        assert!(
            capacity_row_residues(&trace, inactive_memory_row)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
    }
    #[test]
    fn fixed_capacity_exact_length_is_enforced_in_builder_and_relation() {
        assert!(matches!(
            build_sha_word_capacity_trace_v1(&[0_u8; 126], 127, true, challenges()),
            Err(ZkX509ShaWordStarkErrorV1::Topology)
        ));
        let mut trace = build_sha_word_capacity_trace_v1(&[0_u8; 127], 127, true, challenges())
            .expect("exact capacity");
        assert!(trace.exact_length);
        let last = trace.logical_rows() - 1;
        assert_eq!(
            trace.fixed_rows[last][SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1],
            F(127)
        );
        assert_eq!(
            trace.fixed_rows[last][SHA_WORD_CAPACITY_EXACT_LENGTH_V1],
            F::ONE
        );
        trace.aux_rows[last][SHA_WORD_CAPACITY_MESSAGE_COUNT_V1] =
            trace.aux_rows[last][SHA_WORD_CAPACITY_MESSAGE_COUNT_V1].sub(F::ONE);
        assert!(
            capacity_row_residues(&trace, last)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
    }
    fn aggregate_row_residues(
        schedule: &ZkX509ShaWordStarkFixedScheduleV1,
        trace: &ZkX509ShaWordStarkTraceV1,
        index: usize,
        challenges: ZkX509ShaWordStarkChallengesV1,
    ) -> Vec<F> {
        let next = (index + 1) % SHA_WORD_AGGREGATE_TRACE_SIZE_V1;
        evaluate_zk_x509_sha_word_stark_residues_v1(
            &zk_x509_sha_word_stark_aggregate_base_row_v1(trace, index).expect("current base"),
            &zk_x509_sha_word_stark_aggregate_base_row_v1(trace, next).expect("next base"),
            &zk_x509_sha_word_stark_aggregate_aux_row_v1(schedule, trace, index)
                .expect("current aux"),
            &zk_x509_sha_word_stark_aggregate_aux_row_v1(schedule, trace, next).expect("next aux"),
            &schedule.fixed_row_v1(index).expect("fixed row"),
            challenges,
        )
        .expect("numeric residue vector")
    }
    #[test]
    fn aggregate_numeric_evaluator_accepts_every_active_row_and_exact_padding_boundaries() {
        let trace = fixture();
        let schedule = compile_zk_x509_sha_word_stark_fixed_schedule_v1(trace.base.statement)
            .expect("fixed aggregate schedule");
        assert_eq!(schedule.logical_rows(), trace.base.base_rows.len());
        assert_eq!(schedule.aggregate_rows(), 1 << 20);
        assert_eq!(schedule.local_rows(), trace.base.local_rows);
        assert_eq!(schedule.memory_rows(), trace.base.execution.len());
        for index in 0..schedule.logical_rows() {
            let residues = aggregate_row_residues(&schedule, trace, index, stark_challenges());
            assert_eq!(residues.len(), SHA_WORD_STARK_CONSTRAINT_COUNT_V1);
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "nonzero numeric residue at active row {index}"
            );
        }
        let first_padding = schedule.logical_rows();
        for index in [
            first_padding,
            SHA_WORD_LOGICAL_SLOT_ROWS_V1 - 1,
            SHA_WORD_LOGICAL_SLOT_ROWS_V1,
            SHA_WORD_AGGREGATE_TRACE_SIZE_V1 - 1,
        ] {
            let residues = aggregate_row_residues(&schedule, trace, index, stark_challenges());
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "nonzero numeric residue at aggregate boundary row {index}"
            );
        }
        let first_padding_fixed = schedule
            .fixed_row_v1(first_padding)
            .expect("first padding fixed row");
        assert_eq!(first_padding_fixed[FIX_PADDING], F::ONE);
        let midpoint_fixed = schedule
            .fixed_row_v1(SHA_WORD_LOGICAL_SLOT_ROWS_V1 - 1)
            .expect("midpoint predecessor");
        assert_eq!(midpoint_fixed[FIX_PHYSICAL_BOUNDARY], F::ONE);
        assert_eq!(midpoint_fixed[FIX_CONTINUATION_WITHIN_SLOT], F::ZERO);
        let final_fixed = schedule
            .fixed_row_v1(SHA_WORD_AGGREGATE_TRACE_SIZE_V1 - 1)
            .expect("final fixed row");
        assert_eq!(final_fixed[FIX_LAST_AGGREGATE_ROW], F::ONE);
        assert_eq!(final_fixed[FIX_PADDING], F::ONE);
        assert_eq!(final_fixed[FIX_CONTINUATION_WITHIN_SLOT], F::ZERO);
    }
    #[test]
    fn aggregate_profile_inventory_and_degree_are_exact() {
        assert_eq!(SHA_WORD_AGGREGATE_TRACE_LOG2_V1, 20);
        assert_eq!(SHA_WORD_LOGICAL_SLOT_LOG2_V1, 19);
        assert_eq!(SHA_WORD_STARK_FIXED_WIDTH_V1, 55);
        assert_eq!(SHA_WORD_STARK_BASE_ERROR_COUNT_V1, 441);
        assert_eq!(SHA_WORD_COPY_LANES_V1, 4);
        assert_eq!(SHA_WORD_LOCAL_PRODUCT_WIDTH_V1, 24);
        assert_eq!(SHA_WORD_MEMORY_PRODUCT_WIDTH_V1, 16);
        assert_eq!(SHA_WORD_CONTINUATION_WIDTH_V1, 23);
        assert_eq!(SHA_WORD_AUX_WIDTH_V1, 51);
        assert_eq!(SHA_WORD_STARK_CONSTRAINT_COUNT_V1, 155);
        assert_eq!(SHA_WORD_STARK_CONSTRAINT_DEGREE_V1, 4);
        assert_eq!(
            GLOBAL_LOCAL_PRODUCT_END + SHA_WORD_COPY_LANES_V1,
            SHA_WORD_AUX_WIDTH_V1
        );
        assert_eq!(FIX_CONTINUATION_PUBLIC + 7, SHA_WORD_STARK_FIXED_WIDTH_V1);
    }
    #[test]
    fn aggregate_active_and_padding_columns_fail_closed_under_mutation() {
        let trace = fixture();
        let schedule = compile_zk_x509_sha_word_stark_fixed_schedule_v1(trace.base.statement)
            .expect("fixed aggregate schedule");
        let representative_rows = [
            trace
                .base
                .fixed_rows
                .iter()
                .position(|row| matches!(row, ShaWordFixedRowV1::Word { .. }))
                .expect("word row"),
            trace
                .base
                .fixed_rows
                .iter()
                .position(|row| matches!(row, ShaWordFixedRowV1::Sigma { .. }))
                .expect("sigma row"),
            trace
                .base
                .fixed_rows
                .iter()
                .position(|row| matches!(row, ShaWordFixedRowV1::Choose { .. }))
                .expect("choose row"),
            trace
                .base
                .fixed_rows
                .iter()
                .position(|row| matches!(row, ShaWordFixedRowV1::Majority { .. }))
                .expect("majority row"),
            trace
                .base
                .fixed_rows
                .iter()
                .position(|row| matches!(row, ShaWordFixedRowV1::Add { .. }))
                .expect("add row"),
            trace
                .base
                .fixed_rows
                .iter()
                .position(|row| matches!(row, ShaWordFixedRowV1::Digest { .. }))
                .expect("digest row"),
            trace.base.local_rows,
            schedule.logical_rows(),
        ];
        for index in representative_rows {
            let next_index = (index + 1) % SHA_WORD_AGGREGATE_TRACE_SIZE_V1;
            let canonical_base =
                zk_x509_sha_word_stark_aggregate_base_row_v1(trace, index).expect("base");
            let next_base =
                zk_x509_sha_word_stark_aggregate_base_row_v1(trace, next_index).expect("next base");
            let canonical_aux =
                zk_x509_sha_word_stark_aggregate_aux_row_v1(&schedule, trace, index).expect("aux");
            let next_aux =
                zk_x509_sha_word_stark_aggregate_aux_row_v1(&schedule, trace, next_index)
                    .expect("next aux");
            let fixed = schedule.fixed_row_v1(index).expect("fixed");
            for column in 0..SHA_WORD_BASE_WIDTH_V1 {
                let mut changed = canonical_base;
                changed[column] = changed[column].add(F::ONE);
                let residues = evaluate_zk_x509_sha_word_stark_residues_v1(
                    &changed,
                    &next_base,
                    &canonical_aux,
                    &next_aux,
                    &fixed,
                    stark_challenges(),
                )
                .expect("mutated base residues");
                assert!(
                    residues.iter().any(|residue| *residue != F::ZERO),
                    "unbound base column {column} at row {index}"
                );
            }
            for column in 0..SHA_WORD_AUX_WIDTH_V1 {
                let mut changed = canonical_aux;
                changed[column] = changed[column].add(F::ONE);
                let residues = evaluate_zk_x509_sha_word_stark_residues_v1(
                    &canonical_base,
                    &next_base,
                    &changed,
                    &next_aux,
                    &fixed,
                    stark_challenges(),
                )
                .expect("mutated aux residues");
                assert!(
                    residues.iter().any(|residue| *residue != F::ZERO),
                    "unbound aux column {column} at row {index}"
                );
            }
        }
    }
    #[test]
    fn aggregate_memory_and_folding_challenges_fail_closed() {
        let trace = fixture();
        let schedule = compile_zk_x509_sha_word_stark_fixed_schedule_v1(trace.base.statement)
            .expect("fixed aggregate schedule");
        for lane_index in 0..SHA_WORD_COPY_LANES_V1 {
            for coefficient in 0..4 {
                let rejected = (trace.base.local_rows..schedule.logical_rows()).any(|index| {
                    let next_index = index + 1;
                    let current =
                        zk_x509_sha_word_stark_aggregate_base_row_v1(trace, index).expect("base");
                    let next = zk_x509_sha_word_stark_aggregate_base_row_v1(trace, next_index)
                        .expect("next");
                    let current_aux =
                        zk_x509_sha_word_stark_aggregate_aux_row_v1(&schedule, trace, index)
                            .expect("aux");
                    let next_aux =
                        zk_x509_sha_word_stark_aggregate_aux_row_v1(&schedule, trace, next_index)
                            .expect("next aux");
                    let fixed = schedule.fixed_row_v1(index).expect("fixed");
                    let mut changed = stark_challenges();
                    let lane = &mut changed.memory.lanes[lane_index];
                    match coefficient {
                        0 => lane.beta = lane.beta.add(F::ONE),
                        1 => lane.address = lane.address.add(F::ONE),
                        2 => lane.value = lane.value.add(F::ONE),
                        _ => lane.is_write = lane.is_write.add(F::ONE),
                    }
                    evaluate_zk_x509_sha_word_stark_residues_v1(
                        &current,
                        &next,
                        &current_aux,
                        &next_aux,
                        &fixed,
                        changed,
                    )
                    .expect("changed challenge residues")
                    .iter()
                    .any(|residue| *residue != F::ZERO)
                });
                assert!(
                    rejected,
                    "unbound memory challenge lane {lane_index} coefficient {coefficient}"
                );
            }
        }
        let memory_index = trace.base.local_rows;
        let current =
            zk_x509_sha_word_stark_aggregate_base_row_v1(trace, memory_index).expect("base");
        let next =
            zk_x509_sha_word_stark_aggregate_base_row_v1(trace, memory_index + 1).expect("next");
        let current_aux =
            zk_x509_sha_word_stark_aggregate_aux_row_v1(&schedule, trace, memory_index)
                .expect("aux");
        let next_aux =
            zk_x509_sha_word_stark_aggregate_aux_row_v1(&schedule, trace, memory_index + 1)
                .expect("next aux");
        let fixed = schedule.fixed_row_v1(memory_index).expect("fixed");
        let mut zero = stark_challenges();
        zero.base_folding[0] = F::ZERO;
        assert_eq!(
            evaluate_zk_x509_sha_word_stark_residues_v1(
                &current,
                &next,
                &current_aux,
                &next_aux,
                &fixed,
                zero,
            )
            .expect_err("zero folding challenge"),
            ZkX509ShaWordStarkErrorV1::LocalConstraint
        );
        let mut duplicate = stark_challenges();
        duplicate.base_folding[1] = duplicate.base_folding[0];
        assert_eq!(
            evaluate_zk_x509_sha_word_stark_residues_v1(
                &current,
                &next,
                &current_aux,
                &next_aux,
                &fixed,
                duplicate,
            )
            .expect_err("duplicate folding challenge"),
            ZkX509ShaWordStarkErrorV1::LocalConstraint
        );
    }
    #[test]
    fn compiled_maximum_requires_exactly_two_physical_segments_without_allocating_it() {
        let rows = sha256_word_total_rows_for_message_len_v1(ZK_X509_DER_MAX_DOCUMENT_BYTES_V1)
            .expect("bounded maximum")
            .checked_add(8)
            .expect("eight digest rows");
        let segment_rows = SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1;
        assert!(rows > segment_rows);
        assert!(rows <= segment_rows * 2);
    }
    #[test]
    fn continuations_cross_the_local_memory_boundary_exactly() {
        let base = ZkX509ShaWordStarkBaseV1 {
            statement: ZkX509ShaWordStarkStatementV1 {
                message_len: 0,
                digest: [0; 32],
            },
            base_rows: vec![vec![F::ZERO; SHA_WORD_BASE_WIDTH_V1]; 7],
            fixed_rows: vec![ShaWordFixedRowV1::Padding; 7],
            local_events: vec![Vec::new(); 3],
            execution: vec![
                WordMemoryAccessV1 {
                    address: F::ZERO,
                    value: F::ZERO,
                    is_write: F::ONE,
                };
                4
            ],
            sorted: vec![
                WordMemoryAccessV1 {
                    address: F::ZERO,
                    value: F::ZERO,
                    is_write: F::ONE,
                };
                4
            ],
            local_rows: 3,
            segment_rows: 4,
            active_rows_per_segment: vec![4, 3],
        };
        let products = (0_u64..4)
            .map(|index| {
                let mut row = [F::ZERO; SHA_WORD_MEMORY_PRODUCT_WIDTH_V1];
                row[MEMORY_EXEC_AFTER..MEMORY_EXEC_AFTER + SHA_WORD_COPY_LANES_V1]
                    .fill(F(index + 2));
                row[MEMORY_SORT_AFTER..MEMORY_SORT_AFTER + SHA_WORD_COPY_LANES_V1]
                    .fill(F(index + 2));
                row
            })
            .collect::<Vec<_>>();
        let continuations = build_continuations(&base, &products).expect("two continuations");
        assert_eq!(continuations.len(), 2);
        assert_eq!(
            (
                continuations[0].local_row_start,
                continuations[0].local_row_end,
                continuations[0].memory_row_start,
                continuations[0].memory_row_end,
            ),
            (0, 3, 0, 1)
        );
        assert_eq!(
            (
                continuations[1].local_row_start,
                continuations[1].local_row_end,
                continuations[1].memory_row_start,
                continuations[1].memory_row_end,
            ),
            (3, 3, 1, 4)
        );
        assert_eq!(
            continuations[1].execution_product_start,
            continuations[0].execution_product_end
        );
        assert_eq!(
            continuations[1].sorted_product_start,
            continuations[0].sorted_product_end
        );
    }
    #[test]
    fn statement_resource_digest_and_challenge_failures_are_rejected() {
        let oversized = vec![0_u8; ZK_X509_DER_MAX_DOCUMENT_BYTES_V1 + 1];
        let oversized_statement = ZkX509ShaWordStarkStatementV1 {
            message_len: oversized.len(),
            digest: [0; 32],
        };
        assert_eq!(
            build_sha_word_stark_base_v1(oversized_statement, &oversized)
                .expect_err("oversized message"),
            ZkX509ShaWordStarkErrorV1::Topology
        );
        let mut wrong_statement = fixture().base.statement;
        wrong_statement.digest[0] ^= 1;
        assert_eq!(
            build_sha_word_stark_base_v1(wrong_statement, b"abc").expect_err("wrong public digest"),
            ZkX509ShaWordStarkErrorV1::Topology
        );
        let length_statement = ZkX509ShaWordStarkStatementV1 {
            message_len: 2,
            digest: fixture().base.statement.digest,
        };
        assert_eq!(
            build_sha_word_stark_base_v1(length_statement, b"abc")
                .expect_err("wrong private length"),
            ZkX509ShaWordStarkErrorV1::Topology
        );
        let mut zero = challenges();
        zero.lanes[0].beta = F::ZERO;
        assert_eq!(
            validate_sha_word_stark_trace_v1(fixture(), zero).expect_err("zero challenge"),
            ZkX509ShaWordStarkErrorV1::LocalCopy
        );
        let mut duplicate = challenges();
        duplicate.lanes[1] = duplicate.lanes[0];
        assert_eq!(
            validate_sha_word_stark_trace_v1(fixture(), duplicate)
                .expect_err("duplicate challenge lane"),
            ZkX509ShaWordStarkErrorV1::LocalCopy
        );
    }
    #[test]
    fn every_base_column_is_bound_on_word_and_memory_rows() {
        let word_index = fixture()
            .base
            .fixed_rows
            .iter()
            .position(|fixed| matches!(fixed, ShaWordFixedRowV1::Word { .. }))
            .expect("word row");
        let memory_index = fixture().base.local_rows;
        for column in 0..SHA_WORD_BASE_WIDTH_V1 {
            let mut changed = fixture().clone();
            mutate(&mut changed.base.base_rows[word_index][column]);
            assert!(
                validate_sha_word_stark_trace_v1(&changed, challenges()).is_err(),
                "unbound word base column {column}"
            );
            let mut changed = fixture().clone();
            mutate(&mut changed.base.base_rows[memory_index][column]);
            assert!(
                validate_sha_word_stark_trace_v1(&changed, challenges()).is_err(),
                "unbound memory base column {column}"
            );
        }
    }
    #[test]
    fn every_auxiliary_column_and_all_side_tables_are_bound() {
        for column in 0..SHA_WORD_AUX_WIDTH_V1 {
            let mut changed = fixture().clone();
            mutate(&mut changed.aux_rows[0][column]);
            assert!(
                validate_sha_word_stark_trace_v1(&changed, challenges()).is_err(),
                "unbound auxiliary column {column}"
            );
        }
        let mut changed = fixture().clone();
        changed.base.fixed_rows[0] = ShaWordFixedRowV1::Padding;
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
        let mut changed = fixture().clone();
        mutate(&mut changed.base.local_events[0][0].value);
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
        let mut changed = fixture().clone();
        mutate(&mut changed.base.execution[0].value);
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
        let mut changed = fixture().clone();
        mutate(&mut changed.base.sorted[0].value);
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
        let mut changed = fixture().clone();
        changed.continuations[0].global_row_end -= 1;
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
        let mut changed = fixture().clone();
        changed.base.statement.digest[0] ^= 1;
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
        let mut changed = fixture().clone();
        changed.base.base_rows[0][0] = F(u64::MAX);
        assert!(validate_sha_word_stark_trace_v1(&changed, challenges()).is_err());
    }
    #[test]
    fn add_output_above_u32_cannot_trade_against_the_carry() {
        let mut changed = fixture().clone();
        let add_index = changed
            .base
            .fixed_rows
            .iter()
            .enumerate()
            .find_map(|(index, fixed)| {
                matches!(fixed, ShaWordFixedRowV1::Add { .. })
                    .then(|| {
                        let row = &changed.base.base_rows[index];
                        let carry = row[6].0 + 2 * row[7].0 + 4 * row[8].0;
                        (carry > 0).then_some(index)
                    })
                    .flatten()
            })
            .expect("addition with nonzero carry");
        let (arity, constant) = match &changed.base.fixed_rows[add_index] {
            ShaWordFixedRowV1::Add {
                arity, constant, ..
            } => (usize::from(*arity), *constant),
            _ => unreachable!("selected add"),
        };
        let row = &mut changed.base.base_rows[add_index];
        let carry = row[6].0 + 2 * row[7].0 + 4 * row[8].0;
        row[5] = row[5].add(F(1_u64 << 32));
        let lower_carry = carry - 1;
        for bit in 0..3 {
            row[6 + bit] = F((lower_carry >> bit) & 1);
        }
        assert_eq!(
            row[..arity]
                .iter()
                .copied()
                .fold(F(u64::from(constant)), F::add),
            row[5].add(F(1_u64 << 32).mul(F(lower_carry))),
            "the old addition equation alone accepts this alternate decomposition"
        );
        assert_eq!(
            validate_local_rows(&changed.base).expect_err("u32 range must reject it"),
            ZkX509ShaWordStarkErrorV1::LocalConstraint
        );
    }
}

#[cfg(test)]
#[path = "sha_word_stark_polynomial_tests.rs"]
mod polynomial_tests;
