//! Closed algebraic compiler for the verifier-owned zk-X509 SHA schedule.
//!
//! The compiler derives every fixed value from the public disclosure shape
//! and the native SHA circuit topology. It never constructs a native
//! `rows × width` matrix, a common-domain LDE, a Merkle tree, or a
//! proof-supplied fixed opening. Instead it walks the typed word-operation and
//! word-memory schedules once and emits canonical affine, repeated, and sparse
//! atoms for all four physical log19 SHA segments.
#[cfg(test)]
use super::fixed_algebraic::ZkX509FixedAlgebraicOpeningsV1;
use super::{
    fixed_algebraic::{
        ZkX509FixedAlgebraicAtomV1, ZkX509FixedAlgebraicDomainV1, ZkX509FixedAlgebraicErrorV1,
        ZkX509FixedAlgebraicScheduleBuilderV1, ZkX509FixedAlgebraicScheduleV1,
    },
    profile::ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
    sha_call_bus_stark::{
        ZK_X509_SHA_BATCH_FIXED_WIDTH_V1, ZK_X509_SHA_CA_CALL_COUNT_V1,
        ZK_X509_SHA_CA_LEAF_CALL_V1, ZK_X509_SHA_CALL_COUNT_V1,
        ZK_X509_SHA_FIXED_CA_CALL_SELECTORS_V1, ZK_X509_SHA_FIXED_CALL_V1,
        ZK_X509_SHA_FIXED_PHYSICAL_PADDING_V1, ZK_X509_SHA_FIXED_ROLE_V1,
        ZK_X509_SHA_FIXED_SEGMENT_FIRST_V1, ZK_X509_SHA_FIXED_SEGMENT_LAST_V1,
        ZK_X509_SHA_FIXED_SLOT_V1, ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1,
        ZK_X509_SHA_SEGMENT_COUNT_V1, ZK_X509_SHA_SEGMENT_ROWS_V1, ZkX509ShaCallBusStarkErrorV1,
        ZkX509ShaCallManifestV1, ZkX509ShaCallPublicShapeV1, ZkX509ShaCallRoleV1,
        ZkX509ShaCallScheduleV1, ZkX509ShaRfcConsumerChannelsV1, sha_rfc_consumer_channels_v1,
    },
    sha_word_stark::{
        SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1, SHA_WORD_CAPACITY_BLOCK_FIRST_V1,
        SHA_WORD_CAPACITY_BLOCK_LAST_V1, SHA_WORD_CAPACITY_CALL_FIRST_V1,
        SHA_WORD_CAPACITY_CALL_LAST_V1, SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1,
        SHA_WORD_CAPACITY_EXACT_LENGTH_V1, SHA_WORD_CAPACITY_FIXED_WIDTH_V1,
        SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1, SHA_WORD_CAPACITY_INPUT_WORD_V1,
        SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1, SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1,
        SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1, SHA_WORD_CAPACITY_MAX_BLOCK_LAST_V1,
        SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1, SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1,
        SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1,
    },
    sha256_word_air::{
        SigmaThirdV1, WordMemoryAccessV1, WordOperationV1, ZkX509Sha256WordCircuitV1,
        build_sha256_word_circuit_v1,
    },
    stark::ZK_X509_FIXED_DIGEST_CONTEXT_V1,
};
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_GENERATOR_V1, GoldilocksFieldV1 as F, GoldilocksFp4V1 as E, PrivacyOuterDigestV1,
    privacy_outer_digest_frame_v1,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
use thiserror::Error;
/// Exact first-release algebraic SHA compiler description.
pub const ZK_X509_SHA_FIXED_ALGEBRAIC_COMPILER_DESCRIPTOR_V1: &[u8] =
    b"zk-x509-sha-fixed-algebraic-compiler-v1-incompatible:public-shapes=disclosed-attributes0through4:four-independent-physical-log19-generic-children:child-widths=118,118,118,118:combined-width472:segment-major-column-order:each-child-generic-cap65536:typed-composite-digest=sha3-384-opaque48-binds-disclosure-shape+profile+ordered-widths+ordered-child-digests:row-major-child-opening-concatenation:typed-zero-capacity-sha-word-circuit-topology:word-operation-and-execution-sorted-memory-walk:authoritative-local-row-event-order-replay:definition-writes-immediately-before-consuming-operation:operation-input-reads-then-output-write:eight-digest-reads-last:derived-execution-sort-must-equal-circuit-canonical-sorted-memory:execution-write-axis-key=typed-word-phase(initial|input|expansion3|round8|final):compute+execution+sorted-memory-call-axis-transpose-on-exact-maximal-contiguous-same-segment-same-geometry-runs-iff-calls-strictly-greater-than-blocks:block-row-axis-on-ties:boolean-topology-three-way-exact-atom-planner(block-or-call=2048*min(calls,blocks)|round=32*blocks*calls|block-gap=416*calls):strict-lower-only:old-then-round-wins-ties:block-gap-axis-one-stride14-hull+12-negative-stride1064-gap-residues-per-lane:operation-read-typed-block+phase(expansion6|round18|final2)+read-slot-axis-with-exact-per-call-cost44*blocks-2:operation-read-axis-transpose-iff-exact-cost-strictly-less-than-existing-block-or-call-axis:sorted-memory-typed-initial-or-block+word-phase(initial|input|expansion3|round8|final)+access-occurrence-axis:sorted-memory-phase-axis-on-every-exact-geometry-run-iff-phase-cost=298*blocks*calls-is-strictly-less-than-existing-axis-cost(call=4952*blocks+32|block=(4952+32)*calls):old-axis-wins-ties:call-axis-key=local-column+family+block(initial-or-sha-index)+word-position+occurrence:remaining-sorted-memory-nontransposed-series-maximal-across-ordered-calls:no-native-row-matrix:no-lde-matrix:no-artifact:no-merkle-root:no-proof-supplied-fixed-values:affine+repeated+sparse-atoms:generator-coset-log19-to-log22:call-role-slot-boundaries+compact-ca-selectors+field-native-rfc-events+physical-padding:exact-shape-derived-rfc-channel-offsets:all-six-formerly-reconstructed-word-columns-native:first-release";
#[cfg(test)]
const SHA_COMPILER_DESCRIPTOR_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:sha-fixed-algebraic-compiler:v1";
const SHA_COMPOSITE_DESCRIPTOR_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:sha-fixed-algebraic-composite:v1";
/// Exact width of the combined four-segment SHA algebraic schedule.
pub const ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1: usize =
    ZK_X509_SHA_SEGMENT_COUNT_V1 * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
/// Conservative ceiling for atoms emitted by the structural compiler.
///
/// This is an allocation guard, not a consensus-tunable parameter. The
/// canonical five schedules are required by tests to stay below it.
pub const ZK_X509_SHA_FIXED_ALGEBRAIC_MAX_ATOMS_V1: usize = 65_536;
const SHA_FIXED_ALGEBRAIC_CHILD_ATOM_COUNTS_V1: [usize; ZK_X509_SHA_SEGMENT_COUNT_V1] =
    [55_703, 64_091, 34_614, 45_994];
// Exact raw SHA-word fixed-column positions. These are deliberately repeated
// here because the source module keeps the implementation-only names private;
// exhaustive differential tests bind these positions to `fixed_row_v1`.
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
const FIX_LOCAL_FIRST: usize = 12;
const FIX_LOCAL_CONTINUE: usize = 13;
const FIX_LOCAL_LAST: usize = 14;
const FIX_MEMORY_CONTINUE: usize = 15;
const FIX_MEMORY_SAME_NEXT: usize = 16;
const FIX_MEMORY_NEW_NEXT: usize = 17;
const FIX_MEMORY_FIRST_SEGMENT: usize = 18;
const FIX_MEMORY_LAST_SEGMENT: usize = 19;
const FIX_FIRST_AGGREGATE_ROW: usize = 20;
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
const FIX_CONTINUATION_GLOBAL_END: usize = 50;
const FIX_CONTINUATION_LOCAL_END: usize = 52;
const FIX_CONTINUATION_MEMORY_END: usize = 54;
const SHA_FIXED_RFC_LENGTH_PAIR_V1: usize =
    ZK_X509_SHA_FIXED_CA_CALL_SELECTORS_V1 + ZK_X509_SHA_CA_CALL_COUNT_V1;
const SHA_FIXED_RFC_LENGTH_PAIR_INDEX_V1: usize = SHA_FIXED_RFC_LENGTH_PAIR_V1 + 1;
const SHA_FIXED_RFC_LENGTH_PREFIX_V1: usize = SHA_FIXED_RFC_LENGTH_PAIR_INDEX_V1 + 1;
const SHA_FIXED_RFC_STREAMS_V1: usize = SHA_FIXED_RFC_LENGTH_PREFIX_V1 + 1;
const SHA_FIXED_RFC_STREAM_STRIDE_V1: usize = 6;
const SHA_FIXED_RFC_MESSAGE_EVENT_V1: usize = 0;
const SHA_FIXED_RFC_LENGTH_HIGH_VALUE_V1: usize = 1;
const SHA_FIXED_RFC_LENGTH_LOW_VALUE_V1: usize = 2;
const SHA_FIXED_RFC_ROLE_V1: usize = 3;
const SHA_FIXED_RFC_CHANNEL_V1: usize = 4;
const SHA_FIXED_RFC_OFFSET_V1: usize = 5;
const INITIAL_LOCAL_ROWS_PER_CALL_V1: usize = 8;
const DIGEST_LOCAL_ROWS_PER_CALL_V1: usize = 8;
const FIXED_MEMORY_ROWS_PER_CALL_V1: usize = 16;
const REPEAT_FAMILY_COMPUTE_V1: u8 = 0;
const REPEAT_FAMILY_EXECUTION_READ_V1: u8 = 1;
const REPEAT_FAMILY_SORTED_MEMORY_V1: u8 = 2;
const CALL_AXIS_UNKEYED_OCCURRENCE_V1: u32 = 0;
const SHA_ROUNDS_PER_BLOCK_V1: usize = 64;
const SHA_ROUND_ROWS_V1: usize = 14;
const SHA_ROUND_REGION_OFFSET_V1: usize = 160;
const SHA_CHOOSE_ROUND_OFFSET_V1: usize = 1;
const SHA_MAJORITY_ROUND_OFFSET_V1: usize = 7;
const SHA_BOOLEAN_BLOCK_OR_CALL_AXIS_ATOMS_V1: usize = 2_048;
const SHA_BOOLEAN_ROUND_AXIS_ATOMS_PER_BLOCK_V1: usize = 32;
const SHA_BOOLEAN_LANES_V1: usize = 32;
const SHA_BOOLEAN_BLOCK_LATTICE_STEPS_V1: usize = 76;
const SHA_BOOLEAN_BLOCK_GAP_RESIDUES_V1: usize = 12;
const SHA_BOOLEAN_BLOCK_GAP_ATOMS_PER_CALL_V1: usize = 416;
const SHA_OPERATION_READS_PER_BLOCK_V1: usize = 1_456;
const SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1: usize = 288;
const SHA_OPERATION_ROUND_READS_PER_BLOCK_V1: usize = 1_152;
const SHA_OPERATION_FINAL_READS_PER_BLOCK_V1: usize = 16;
const SHA_OPERATION_EXPANSION_READ_SLOTS_V1: usize = 6;
const SHA_OPERATION_ROUND_READ_SLOTS_V1: usize = 18;
const SHA_OPERATION_FINAL_READ_SLOTS_V1: usize = 2;
const SHA_OPERATION_FIRST_BLOCK_NONZERO_READS_V1: usize = 1_450;
const SHA_OPERATION_AXIS_FIRST_BLOCK_ATOMS_V1: usize = 42;
const SHA_OPERATION_AXIS_LATER_BLOCK_ATOMS_V1: usize = 44;
const SHA_WORDS_PER_BLOCK_V1: usize = 680;
const SHA_SORTED_PHASE_AXIS_ATOMS_PER_BLOCK_V1: usize = 298;
const SHA_SORTED_CALL_AXIS_ATOMS_PER_BLOCK_V1: usize = 4_952;
const SHA_SORTED_CALL_AXIS_FIXED_ATOMS_V1: usize = 32;
static ZK_X509_SHA_FIXED_ALGEBRAIC_SCHEDULES_V1: [OnceLock<ZkX509ShaFixedAlgebraicScheduleV1>; 5] =
    [const { OnceLock::new() }; 5];
const _: () = {
    assert!(ZK_X509_SHA_CALL_COUNT_V1 == 29);
    assert!(ZK_X509_SHA_SEGMENT_COUNT_V1 == 4);
    assert!(ZK_X509_SHA_SEGMENT_ROWS_V1 == 1 << 19);
    assert!(ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 == 118);
    assert!(ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1 == 472);
    assert!(SHA_WORD_CAPACITY_FIXED_WIDTH_V1 == 72);
    assert!(ZK_X509_SHA_FIXED_CALL_V1 == SHA_WORD_CAPACITY_FIXED_WIDTH_V1);
    assert!(ZK_X509_SHA_FIXED_ROLE_V1 == 73);
    assert!(ZK_X509_SHA_FIXED_SLOT_V1 == 74);
    assert!(ZK_X509_SHA_FIXED_SEGMENT_FIRST_V1 == 75);
    assert!(ZK_X509_SHA_FIXED_SEGMENT_LAST_V1 == 76);
    assert!(ZK_X509_SHA_FIXED_PHYSICAL_PADDING_V1 == 77);
    assert!(ZK_X509_SHA_FIXED_CA_CALL_SELECTORS_V1 == 78);
    assert!(SHA_FIXED_RFC_LENGTH_PAIR_V1 == 91);
    assert!(SHA_FIXED_RFC_STREAMS_V1 == 94);
    assert!(
        SHA_FIXED_RFC_STREAMS_V1 + 4 * SHA_FIXED_RFC_STREAM_STRIDE_V1
            == ZK_X509_SHA_BATCH_FIXED_WIDTH_V1
    );
    assert!(
        SHA_ROUND_REGION_OFFSET_V1 + SHA_ROUNDS_PER_BLOCK_V1 * SHA_ROUND_ROWS_V1 + 8
            == SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1
    );
    assert!(
        SHA_BOOLEAN_BLOCK_LATTICE_STEPS_V1 * SHA_ROUND_ROWS_V1
            == SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1
    );
    assert!(
        SHA_ROUNDS_PER_BLOCK_V1 + SHA_BOOLEAN_BLOCK_GAP_RESIDUES_V1
            == SHA_BOOLEAN_BLOCK_LATTICE_STEPS_V1
    );
    assert!(
        SHA_BOOLEAN_LANES_V1 * (1 + SHA_BOOLEAN_BLOCK_GAP_RESIDUES_V1)
            == SHA_BOOLEAN_BLOCK_GAP_ATOMS_PER_CALL_V1
    );
    assert!(SHA_MAJORITY_ROUND_OFFSET_V1 + 4 <= SHA_ROUND_ROWS_V1);
    assert!(
        SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1
            + SHA_OPERATION_ROUND_READS_PER_BLOCK_V1
            + SHA_OPERATION_FINAL_READS_PER_BLOCK_V1
            == SHA_OPERATION_READS_PER_BLOCK_V1
    );
    assert!(
        SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1 % SHA_OPERATION_EXPANSION_READ_SLOTS_V1 == 0
    );
    assert!(SHA_OPERATION_ROUND_READS_PER_BLOCK_V1 % SHA_OPERATION_ROUND_READ_SLOTS_V1 == 0);
    assert!(SHA_OPERATION_FINAL_READS_PER_BLOCK_V1 % SHA_OPERATION_FINAL_READ_SLOTS_V1 == 0);
    assert!(
        SHA_WORDS_PER_BLOCK_V1 + SHA_OPERATION_READS_PER_BLOCK_V1
            == SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1
    );
};
/// Structural SHA fixed-schedule compilation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509ShaFixedAlgebraicErrorV1 {
    /// The public shape or verifier-owned SHA topology is invalid.
    #[error("zk-X509 algebraic SHA fixed topology is invalid")]
    Topology,
    /// Checked row, column, or allocation arithmetic exceeded the profile.
    #[error("zk-X509 algebraic SHA fixed resource envelope is exceeded")]
    Resource,
    /// The generic algebraic schedule rejected a non-canonical atom.
    #[error("zk-X509 algebraic SHA fixed schedule is invalid")]
    Algebraic,
}
impl From<ZkX509FixedAlgebraicErrorV1> for ZkX509ShaFixedAlgebraicErrorV1 {
    fn from(_: ZkX509FixedAlgebraicErrorV1) -> Self {
        Self::Algebraic
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NonzeroPointV1 {
    row: u64,
    value: F,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ShaAtomAccountingV1 {
    total_atoms: usize,
    atoms_by_column: Vec<usize>,
    child_digests: [PrivacyOuterDigestV1; ZK_X509_SHA_SEGMENT_COUNT_V1],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonzeroSeriesV1 {
    Empty,
    One(NonzeroPointV1),
    Two(NonzeroPointV1, NonzeroPointV1),
    Affine {
        first: NonzeroPointV1,
        last: NonzeroPointV1,
        step: F,
    },
    Repeated {
        first: NonzeroPointV1,
        last_row: u64,
        last_value: F,
        count: u64,
        stride: u64,
        step: F,
    },
}
/// Detect an affine value sequence from its two successive field differences.
fn same_successive_value_step_v1(first: F, second: F, third: F) -> bool {
    let first_step = second.sub(first);
    let next_step = third.sub(second);
    first_step == next_step
}

impl NonzeroSeriesV1 {
    const fn empty_v1() -> Self {
        Self::Empty
    }
    fn push_atom_v1(
        builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
        atom_count: &mut usize,
        atom: ZkX509FixedAlgebraicAtomV1,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        *atom_count = atom_count
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if *atom_count > ZK_X509_SHA_FIXED_ALGEBRAIC_MAX_ATOMS_V1 {
            #[cfg(test)]
            eprintln!("zk-X509 SHA algebraic atom limit exceeded at atom {atom_count}: {atom:?}");
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Resource);
        }
        builder.push_atom_v1(atom)?;
        Ok(())
    }
    fn flush_v1(
        &mut self,
        column: u16,
        builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
        atom_count: &mut usize,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        let state = core::mem::replace(self, Self::Empty);
        match state {
            Self::Empty => Ok(()),
            Self::One(point) => Self::push_atom_v1(
                builder,
                atom_count,
                ZkX509FixedAlgebraicAtomV1::sparse_v1(column, point.row, point.value)?,
            ),
            Self::Two(first, second) if second.row == first.row + 1 => Self::push_atom_v1(
                builder,
                atom_count,
                ZkX509FixedAlgebraicAtomV1::affine_v1(
                    column,
                    first.row,
                    second.row + 1,
                    first.value,
                    second.value.sub(first.value),
                )?,
            ),
            Self::Two(first, second) => Self::push_atom_v1(
                builder,
                atom_count,
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(
                    column,
                    first.row,
                    2,
                    second.row - first.row,
                    first.value,
                    second.value.sub(first.value),
                )?,
            ),
            Self::Affine { first, last, step } => Self::push_atom_v1(
                builder,
                atom_count,
                ZkX509FixedAlgebraicAtomV1::affine_v1(
                    column,
                    first.row,
                    last.row + 1,
                    first.value,
                    step,
                )?,
            ),
            Self::Repeated {
                first,
                count,
                stride,
                step,
                ..
            } => Self::push_atom_v1(
                builder,
                atom_count,
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(
                    column,
                    first.row,
                    count,
                    stride,
                    first.value,
                    step,
                )?,
            ),
        }
    }
    fn observe_v1(
        &mut self,
        column: u16,
        point: NonzeroPointV1,
        builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
        atom_count: &mut usize,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if point.value == F::ZERO || F::canonical(point.value.0).is_none() {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let last_row = match *self {
            Self::Empty => None,
            Self::One(last) | Self::Two(_, last) => Some(last.row),
            Self::Affine { last, .. } => Some(last.row),
            Self::Repeated { last_row, .. } => Some(last_row),
        };
        if last_row.is_some_and(|last_row| point.row <= last_row) {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        match *self {
            Self::Empty => {
                *self = Self::One(point);
            }
            Self::One(first) => {
                *self = Self::Two(first, point);
            }
            Self::Two(first, second) => {
                if second.row == first.row + 1
                    && point.row == second.row + 1
                    && same_successive_value_step_v1(first.value, second.value, point.value)
                {
                    *self = Self::Affine {
                        first,
                        last: point,
                        step: second.value.sub(first.value),
                    };
                } else if second.row - first.row == point.row - second.row
                    && same_successive_value_step_v1(first.value, second.value, point.value)
                {
                    *self = Self::Repeated {
                        first,
                        last_row: point.row,
                        last_value: point.value,
                        count: 3,
                        stride: second.row - first.row,
                        step: second.value.sub(first.value),
                    };
                } else {
                    Self::push_atom_v1(
                        builder,
                        atom_count,
                        ZkX509FixedAlgebraicAtomV1::sparse_v1(column, first.row, first.value)?,
                    )?;
                    *self = Self::Two(second, point);
                }
            }
            Self::Affine { first, last, step }
                if point.row == last.row + 1 && point.value.sub(last.value) == step =>
            {
                *self = Self::Affine {
                    first,
                    last: point,
                    step,
                };
            }
            Self::Repeated {
                first,
                last_row,
                last_value,
                count,
                stride,
                step,
            } if point.row.checked_sub(last_row) == Some(stride)
                && point.value.sub(last_value) == step =>
            {
                *self = Self::Repeated {
                    first,
                    last_row: point.row,
                    last_value: point.value,
                    count: count
                        .checked_add(1)
                        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                    stride,
                    step,
                };
            }
            _ => {
                self.flush_v1(column, builder, atom_count)?;
                *self = Self::One(point);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RepeatZoneAxisV1 {
    /// Keep one series per within-block position and span all SHA blocks.
    Blocks,
    /// Keep one series per block and within-block position across calls.
    ///
    /// `family` prevents compute, execution-read, and sorted-memory series
    /// from aliasing even when their physical columns and positions coincide.
    Calls { family: u8 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CallAxisBlockV1 {
    /// The eight initial SHA state words, which precede all block-local words.
    Initial,
    /// One zero-based SHA block in the repeated word topology.
    Sha(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OperationReadPhaseV1 {
    Expansion,
    Round,
    Final,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BooleanTopologyAxisV1 {
    BlockOrCall,
    Round,
    BlockGap,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SortedWordPhaseV1 {
    Initial,
    Input,
    Expansion,
    Round,
    Final,
}
struct RepeatZoneV1 {
    segment: usize,
    start: usize,
    end: usize,
    period: usize,
    columns: [bool; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1],
    axis: RepeatZoneAxisV1,
    series: BTreeMap<(usize, usize), NonzeroSeriesV1>,
}
struct StructuralBuilderV1 {
    physical_segment: usize,
    inner: ZkX509FixedAlgebraicScheduleBuilderV1,
    series: Vec<NonzeroSeriesV1>,
    repeat_zone: Option<RepeatZoneV1>,
    call_axis_group_active: bool,
    call_axis_series: BTreeMap<(usize, u8, CallAxisBlockV1, u32, u32), NonzeroSeriesV1>,
    keyed_series: BTreeMap<(usize, u8, u8, u32, u32), NonzeroSeriesV1>,
    atom_count: usize,
}
impl StructuralBuilderV1 {
    fn new_v1(
        domain: ZkX509FixedAlgebraicDomainV1,
        physical_segment: usize,
    ) -> Result<Self, ZkX509ShaFixedAlgebraicErrorV1> {
        if physical_segment >= ZK_X509_SHA_SEGMENT_COUNT_V1 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let width = u16::try_from(ZK_X509_SHA_BATCH_FIXED_WIDTH_V1)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let inner = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, width)?;
        let mut series = Vec::new();
        series
            .try_reserve_exact(ZK_X509_SHA_BATCH_FIXED_WIDTH_V1)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        series.resize(
            ZK_X509_SHA_BATCH_FIXED_WIDTH_V1,
            NonzeroSeriesV1::empty_v1(),
        );
        Ok(Self {
            physical_segment,
            inner,
            series,
            repeat_zone: None,
            call_axis_group_active: false,
            call_axis_series: BTreeMap::new(),
            keyed_series: BTreeMap::new(),
            atom_count: 0,
        })
    }
    fn combined_column_v1(
        &self,
        segment: usize,
        local_column: usize,
    ) -> Result<usize, ZkX509ShaFixedAlgebraicErrorV1> {
        if segment != self.physical_segment || local_column >= ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        Ok(local_column)
    }
    fn observe_v1(
        &mut self,
        segment: usize,
        local_column: usize,
        row: usize,
        value: F,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if value == F::ZERO {
            return Ok(());
        }
        if row >= ZK_X509_SHA_SEGMENT_ROWS_V1 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let column = self.combined_column_v1(segment, local_column)?;
        let column_u16 =
            u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let row = u64::try_from(row).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if let Some(zone) = &mut self.repeat_zone
            && segment == zone.segment
            && usize::try_from(row)
                .ok()
                .is_some_and(|row| (zone.start..zone.end).contains(&row))
            && zone.columns[local_column]
        {
            let row_usize =
                usize::try_from(row).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            let relative = row_usize
                .checked_sub(zone.start)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
            let block = relative / zone.period;
            let position = relative % zone.period;
            let series = match zone.axis {
                RepeatZoneAxisV1::Blocks => zone
                    .series
                    .entry((column, position))
                    .or_insert_with(NonzeroSeriesV1::empty_v1),
                RepeatZoneAxisV1::Calls { family } => {
                    if !self.call_axis_group_active {
                        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
                    }
                    self.call_axis_series
                        .entry((
                            column,
                            family,
                            CallAxisBlockV1::Sha(
                                u32::try_from(block)
                                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                            ),
                            u32::try_from(position)
                                .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                            CALL_AXIS_UNKEYED_OCCURRENCE_V1,
                        ))
                        .or_insert_with(NonzeroSeriesV1::empty_v1)
                }
            };
            return series.observe_v1(
                column_u16,
                NonzeroPointV1 { row, value },
                &mut self.inner,
                &mut self.atom_count,
            );
        }
        let (inner, series) = (&mut self.inner, &mut self.series);
        series[column].observe_v1(
            column_u16,
            NonzeroPointV1 { row, value },
            inner,
            &mut self.atom_count,
        )
    }
    fn begin_repeat_zone_v1(
        &mut self,
        segment: usize,
        start: usize,
        end: usize,
        period: usize,
        columns: [bool; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1],
        axis: RepeatZoneAxisV1,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if self.repeat_zone.is_some()
            || segment >= ZK_X509_SHA_SEGMENT_COUNT_V1
            || start >= end
            || end > ZK_X509_SHA_SEGMENT_ROWS_V1
            || period < 2
            || (end - start) % period != 0
            || !columns.iter().any(|selected| *selected)
            || (matches!(axis, RepeatZoneAxisV1::Calls { .. }) && !self.call_axis_group_active)
        {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        self.repeat_zone = Some(RepeatZoneV1 {
            segment,
            start,
            end,
            period,
            columns,
            axis,
            series: BTreeMap::new(),
        });
        Ok(())
    }
    fn finish_repeat_zone_v1(&mut self) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        let zone = self
            .repeat_zone
            .take()
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        if matches!(zone.axis, RepeatZoneAxisV1::Calls { .. }) && !zone.series.is_empty() {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        for ((column, _), mut series) in zone.series {
            series.flush_v1(
                u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                &mut self.inner,
                &mut self.atom_count,
            )?;
        }
        Ok(())
    }
    fn begin_call_axis_group_v1(&mut self) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if self.call_axis_group_active
            || self.repeat_zone.is_some()
            || !self.call_axis_series.is_empty()
        {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        self.call_axis_group_active = true;
        Ok(())
    }
    fn finish_call_axis_group_v1(&mut self) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if !self.call_axis_group_active || self.repeat_zone.is_some() {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        self.call_axis_group_active = false;
        let series = core::mem::take(&mut self.call_axis_series);
        for ((column, _, _, _, _), mut series) in series {
            series.flush_v1(
                u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                &mut self.inner,
                &mut self.atom_count,
            )?;
        }
        Ok(())
    }
    fn observe_family_keyed_v1(
        &mut self,
        segment: usize,
        local_column: usize,
        row: usize,
        family: u8,
        block: CallAxisBlockV1,
        word_position: u32,
        occurrence: u32,
        value: F,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if value == F::ZERO {
            return Ok(());
        }
        if row >= ZK_X509_SHA_SEGMENT_ROWS_V1 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let column = self.combined_column_v1(segment, local_column)?;
        let column_u16 =
            u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let point = NonzeroPointV1 {
            row: u64::try_from(row).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            value,
        };
        if self.call_axis_group_active {
            // Preserve the SHA block and occurrence dimensions while this
            // exact geometry run is transposed. Each key then receives one
            // point per call, including the sorted-address boundary flags
            // that are outside the execution-read repeat zone.
            return self
                .call_axis_series
                .entry((column, family, block, word_position, occurrence))
                .or_insert_with(NonzeroSeriesV1::empty_v1)
                .observe_v1(column_u16, point, &mut self.inner, &mut self.atom_count);
        }
        // On the row/block axis, all repeated SHA blocks deliberately share
        // one key; initial-state words retain a separate namespace.
        self.keyed_series
            .entry((
                column,
                family,
                u8::from(matches!(block, CallAxisBlockV1::Initial)),
                word_position,
                occurrence,
            ))
            .or_insert_with(NonzeroSeriesV1::empty_v1)
            .observe_v1(column_u16, point, &mut self.inner, &mut self.atom_count)
    }
    fn observe_keyed_v1(
        &mut self,
        segment: usize,
        local_column: usize,
        row: usize,
        block: CallAxisBlockV1,
        word_position: u32,
        occurrence: u32,
        value: F,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        self.observe_family_keyed_v1(
            segment,
            local_column,
            row,
            REPEAT_FAMILY_SORTED_MEMORY_V1,
            block,
            word_position,
            occurrence,
            value,
        )
    }
    fn flush_keyed_v1(&mut self) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        let keyed = core::mem::take(&mut self.keyed_series);
        for ((column, _, _, _, _), mut series) in keyed {
            series.flush_v1(
                u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                &mut self.inner,
                &mut self.atom_count,
            )?;
        }
        Ok(())
    }
    fn push_affine_v1(
        &mut self,
        segment: usize,
        local_column: usize,
        start: usize,
        end: usize,
        start_value: F,
        step: F,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if start >= end || end > ZK_X509_SHA_SEGMENT_ROWS_V1 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let column = self.combined_column_v1(segment, local_column)?;
        let atom = ZkX509FixedAlgebraicAtomV1::affine_v1(
            u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            u64::try_from(start).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            u64::try_from(end).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            start_value,
            step,
        )?;
        NonzeroSeriesV1::push_atom_v1(&mut self.inner, &mut self.atom_count, atom)
    }
    fn push_constant_v1(
        &mut self,
        segment: usize,
        local_column: usize,
        start: usize,
        end: usize,
        value: F,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if value == F::ZERO {
            return Ok(());
        }
        self.push_affine_v1(segment, local_column, start, end, value, F::ZERO)
    }
    fn push_repeated_v1(
        &mut self,
        segment: usize,
        local_column: usize,
        first: usize,
        count: usize,
        stride: usize,
        value: F,
    ) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        if count == 0 || stride == 0 || value == F::ZERO {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let last = first
            .checked_add(
                count
                    .checked_sub(1)
                    .and_then(|count| count.checked_mul(stride))
                    .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            )
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if last >= ZK_X509_SHA_SEGMENT_ROWS_V1 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let column = self.combined_column_v1(segment, local_column)?;
        let atom = ZkX509FixedAlgebraicAtomV1::repeated_v1(
            u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            u64::try_from(first).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            u64::try_from(count).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            u64::try_from(stride).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            value,
        )?;
        NonzeroSeriesV1::push_atom_v1(&mut self.inner, &mut self.atom_count, atom)
    }
    fn finish_v1(
        mut self,
    ) -> Result<ZkX509FixedAlgebraicScheduleV1, ZkX509ShaFixedAlgebraicErrorV1> {
        if self.repeat_zone.is_some()
            || self.call_axis_group_active
            || !self.call_axis_series.is_empty()
        {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        self.flush_keyed_v1()?;
        for (column, series) in self.series.iter_mut().enumerate() {
            series.flush_v1(
                u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                &mut self.inner,
                &mut self.atom_count,
            )?;
        }
        self.inner.finish_v1().map_err(Into::into)
    }
}
fn exact_message_length_v1(role: ZkX509ShaCallRoleV1) -> bool {
    matches!(
        role,
        ZkX509ShaCallRoleV1::CrlIssuerSpki
            | ZkX509ShaCallRoleV1::TrustAnchorRecord
            | ZkX509ShaCallRoleV1::CrlRecord
            | ZkX509ShaCallRoleV1::CaLeaf
            | ZkX509ShaCallRoleV1::CaNode(_)
    )
}
fn rfc_consumer_v1(
    manifest: ZkX509ShaCallManifestV1,
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<Option<ZkX509ShaRfcConsumerChannelsV1>, ZkX509ShaFixedAlgebraicErrorV1> {
    sha_rfc_consumer_channels_v1(manifest.call, manifest.role, shape.disclosed_attributes).map_err(
        |error| match error {
            ZkX509ShaCallBusStarkErrorV1::Resource => ZkX509ShaFixedAlgebraicErrorV1::Resource,
            _ => ZkX509ShaFixedAlgebraicErrorV1::Topology,
        },
    )
}
fn emit_common_call_atoms_v1(
    output: &mut StructuralBuilderV1,
    manifest: ZkX509ShaCallManifestV1,
    segment: usize,
    start: usize,
    local_rows: usize,
    memory_rows: usize,
    consumer: Option<ZkX509ShaRfcConsumerChannelsV1>,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let logical_rows = local_rows
        .checked_add(memory_rows)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if logical_rows != manifest.maximum_logical_rows() {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let end = start
        .checked_add(logical_rows)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let local_end = start
        .checked_add(local_rows)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if end > ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[segment] {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    output.push_constant_v1(segment, FIX_CONTINUATION_WITHIN_SLOT, start, end, F::ONE)?;
    output.push_constant_v1(
        segment,
        FIX_CONTINUATION_GLOBAL_END,
        start,
        end,
        F(u64::try_from(logical_rows).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
    )?;
    output.push_constant_v1(
        segment,
        FIX_CONTINUATION_LOCAL_END,
        start,
        end,
        F(u64::try_from(local_rows).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
    )?;
    output.push_constant_v1(
        segment,
        FIX_CONTINUATION_MEMORY_END,
        start,
        end,
        F(u64::try_from(memory_rows).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
    )?;
    output.push_constant_v1(
        segment,
        SHA_WORD_CAPACITY_MAXIMUM_MESSAGE_LEN_V1,
        start,
        end,
        F(u64::try_from(manifest.maximum_message_bytes)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
    )?;
    if exact_message_length_v1(manifest.role) {
        output.push_constant_v1(
            segment,
            SHA_WORD_CAPACITY_EXACT_LENGTH_V1,
            start,
            end,
            F::ONE,
        )?;
    }
    output.push_constant_v1(
        segment,
        ZK_X509_SHA_FIXED_CALL_V1,
        start,
        end,
        F(u64::from(manifest.call)),
    )?;
    output.push_constant_v1(
        segment,
        ZK_X509_SHA_FIXED_ROLE_V1,
        start,
        end,
        F(u64::from(manifest.role.role_code())),
    )?;
    output.push_constant_v1(
        segment,
        ZK_X509_SHA_FIXED_SLOT_V1,
        start,
        end,
        F(u64::from(manifest.role.slot())),
    )?;
    if let Some(selector) = usize::from(manifest.call)
        .checked_sub(ZK_X509_SHA_CA_LEAF_CALL_V1)
        .filter(|selector| *selector < ZK_X509_SHA_CA_CALL_COUNT_V1)
    {
        output.push_constant_v1(
            segment,
            ZK_X509_SHA_FIXED_CA_CALL_SELECTORS_V1 + selector,
            start,
            end,
            F::ONE,
        )?;
    }
    if let Some(consumer) = consumer {
        output.push_constant_v1(
            segment,
            SHA_FIXED_RFC_LENGTH_PREFIX_V1,
            start,
            end,
            F(u64::try_from(consumer.message_prefix_bytes)
                .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
        )?;
    }
    output.observe_v1(segment, FIX_LOCAL_FIRST, start, F::ONE)?;
    output.push_constant_v1(segment, FIX_LOCAL_CONTINUE, start, local_end - 1, F::ONE)?;
    output.observe_v1(segment, FIX_LOCAL_LAST, local_end - 1, F::ONE)?;
    output.push_constant_v1(segment, FIX_MEMORY_CONTINUE, local_end, end - 1, F::ONE)?;
    output.observe_v1(segment, FIX_MEMORY_FIRST_SEGMENT, local_end, F::ONE)?;
    output.observe_v1(segment, FIX_MEMORY_LAST_SEGMENT, end - 1, F::ONE)?;
    output.observe_v1(segment, FIX_FIRST_AGGREGATE_ROW, start, F::ONE)?;
    output.observe_v1(segment, SHA_WORD_CAPACITY_CALL_FIRST_V1, start, F::ONE)?;
    output.observe_v1(segment, SHA_WORD_CAPACITY_CALL_LAST_V1, end - 1, F::ONE)?;
    output.push_constant_v1(segment, FIX_MEMORY, local_end, end, F::ONE)?;
    let compute_start = start
        .checked_add(INITIAL_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let compute_rows = manifest
        .maximum_blocks
        .checked_mul(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let compute_end = compute_start
        .checked_add(compute_rows)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if compute_end
        .checked_add(DIGEST_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?
        != local_end
    {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    output.push_constant_v1(
        segment,
        SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1,
        start,
        start + INITIAL_LOCAL_ROWS_PER_CALL_V1 - 1,
        F::ONE,
    )?;
    output.observe_v1(
        segment,
        SHA_WORD_CAPACITY_BLOCK_LAST_V1,
        start + INITIAL_LOCAL_ROWS_PER_CALL_V1 - 1,
        F::ONE,
    )?;
    output.push_repeated_v1(
        segment,
        SHA_WORD_CAPACITY_BLOCK_FIRST_V1,
        compute_start,
        manifest.maximum_blocks,
        SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1,
        F::ONE,
    )?;
    output.push_repeated_v1(
        segment,
        SHA_WORD_CAPACITY_BLOCK_LAST_V1,
        compute_start + SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1 - 1,
        manifest.maximum_blocks,
        SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1,
        F::ONE,
    )?;
    for block in 0..manifest.maximum_blocks {
        let block_start = compute_start
            .checked_add(
                block
                    .checked_mul(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1)
                    .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            )
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        output.push_constant_v1(
            segment,
            SHA_WORD_CAPACITY_BLOCK_CONTINUE_V1,
            block_start,
            block_start + SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1 - 1,
            F::ONE,
        )?;
    }
    output.observe_v1(
        segment,
        SHA_WORD_CAPACITY_MAX_BLOCK_LAST_V1,
        compute_end - 1,
        F::ONE,
    )?;
    Ok(())
}
fn emit_rfc_message_event_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    row: usize,
    input_word: usize,
    consumer: ZkX509ShaRfcConsumerChannelsV1,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let raw_end = consumer
        .message_prefix_bytes
        .checked_add(consumer.message_capacity_bytes)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    for stream in 0..4 {
        let sha_offset = input_word
            .checked_mul(4)
            .and_then(|offset| offset.checked_add(stream))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if !(consumer.message_prefix_bytes..raw_end).contains(&sha_offset) {
            continue;
        }
        let base = SHA_FIXED_RFC_STREAMS_V1 + stream * SHA_FIXED_RFC_STREAM_STRIDE_V1;
        output.observe_v1(segment, base + SHA_FIXED_RFC_MESSAGE_EVENT_V1, row, F::ONE)?;
        output.observe_v1(
            segment,
            base + SHA_FIXED_RFC_ROLE_V1,
            row,
            F(consumer.role as u64),
        )?;
        output.observe_v1(
            segment,
            base + SHA_FIXED_RFC_CHANNEL_V1,
            row,
            F(u64::from(consumer.message_channel)),
        )?;
        output.observe_v1(
            segment,
            base + SHA_FIXED_RFC_OFFSET_V1,
            row,
            F(u64::try_from(sha_offset - consumer.message_prefix_bytes)
                .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
        )?;
    }
    Ok(())
}
fn emit_word_row_v1(
    output: &mut StructuralBuilderV1,
    circuit: &ZkX509Sha256WordCircuitV1,
    input_indices: &[Option<usize>],
    manifest: ZkX509ShaCallManifestV1,
    consumer: Option<ZkX509ShaRfcConsumerChannelsV1>,
    segment: usize,
    row: usize,
    address: usize,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let word = circuit
        .stark_words_v1()
        .get(address)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    output.observe_v1(segment, FIX_WORD, row, F::ONE)?;
    output.observe_v1(
        segment,
        FIX_EVENT_ADDRESS,
        row,
        F(u64::try_from(address).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
    )?;
    let input_word = input_indices.get(address).copied().flatten();
    for message_byte in 0..4 {
        let fixed = input_word.map_or(true, |input| {
            input
                .checked_mul(4)
                .and_then(|offset| offset.checked_add(message_byte))
                .is_none_or(|offset| offset >= manifest.maximum_message_bytes)
        });
        if fixed {
            // SHA input bytes are big-endian inside the u32 word, while the
            // word AIR's fixed-byte groups follow the little-endian bit
            // decomposition.
            let fixed_byte = input_word.map_or(message_byte, |_| 3 - message_byte);
            output.observe_v1(segment, FIX_WORD_BYTE_MASK + fixed_byte, row, F::ONE)?;
            output.observe_v1(
                segment,
                FIX_WORD_BYTE_EXPECTED + fixed_byte,
                row,
                F((word.value.0 >> (fixed_byte * 8)) & 0xff),
            )?;
        }
    }
    if let Some(input_word) = input_word {
        output.observe_v1(segment, SHA_WORD_CAPACITY_INPUT_WORD_V1, row, F::ONE)?;
        output.observe_v1(
            segment,
            SHA_WORD_CAPACITY_INPUT_WORD_INDEX_V1,
            row,
            F(u64::try_from(input_word).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
        )?;
        output.observe_v1(
            segment,
            SHA_WORD_CAPACITY_LENGTH_HIGH_WORD_V1,
            row,
            F(u64::from(input_word % 16 == 14)),
        )?;
        output.observe_v1(
            segment,
            SHA_WORD_CAPACITY_LENGTH_LOW_WORD_V1,
            row,
            F(u64::from(input_word % 16 == 15)),
        )?;
        for byte in 0..4 {
            let byte_index = input_word
                .checked_mul(4)
                .and_then(|offset| offset.checked_add(byte))
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            if byte_index < manifest.maximum_message_bytes {
                output.observe_v1(
                    segment,
                    SHA_WORD_CAPACITY_MESSAGE_ALLOWED_V1 + byte,
                    row,
                    F::ONE,
                )?;
            }
        }
        if let Some(consumer) = consumer {
            emit_rfc_message_event_v1(output, segment, row, input_word, consumer)?;
        }
    }
    Ok(())
}
fn emit_operation_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    row: &mut usize,
    operation: &WordOperationV1,
    boolean_axis: BooleanTopologyAxisV1,
) -> Result<usize, ZkX509ShaFixedAlgebraicErrorV1> {
    let output_address = match operation {
        WordOperationV1::Sigma {
            input,
            rotate_first,
            rotate_second,
            third,
            output: operation_output,
        } => {
            let selector = match (*rotate_first, *rotate_second, *third) {
                (7, 18, SigmaThirdV1::Shift(3)) => FIX_SIGMA_SMALL_ZERO,
                (17, 19, SigmaThirdV1::Shift(10)) => FIX_SIGMA_SMALL_ONE,
                (2, 13, SigmaThirdV1::Rotate(22)) => FIX_SIGMA_BIG_ZERO,
                (6, 11, SigmaThirdV1::Rotate(25)) => FIX_SIGMA_BIG_ONE,
                _ => return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology),
            };
            output.observe_v1(segment, selector, *row, F::ONE)?;
            output.observe_v1(
                segment,
                FIX_EVENT_ADDRESS,
                *row,
                F(u64::try_from(input.0).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
            )?;
            output.observe_v1(
                segment,
                FIX_EVENT_ADDRESS + 1,
                *row,
                F(u64::try_from(operation_output.0)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
            )?;
            *row = row
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            operation_output.0
        }
        WordOperationV1::Choose {
            x,
            y,
            z,
            output: operation_output,
        }
        | WordOperationV1::Majority {
            x,
            y,
            z,
            output: operation_output,
        } => {
            let addresses = [x.0, y.0, z.0, operation_output.0];
            for chunk in 0..4 {
                if boolean_axis == BooleanTopologyAxisV1::BlockOrCall {
                    output.observe_v1(
                        segment,
                        if matches!(operation, WordOperationV1::Choose { .. }) {
                            FIX_CHOOSE
                        } else {
                            FIX_MAJORITY
                        },
                        *row,
                        F::ONE,
                    )?;
                }
                if chunk == 0 {
                    if boolean_axis == BooleanTopologyAxisV1::BlockOrCall {
                        output.observe_v1(segment, FIX_BOOLEAN_FIRST, *row, F::ONE)?;
                    }
                    for (slot, address) in addresses.iter().copied().enumerate() {
                        output.observe_v1(
                            segment,
                            FIX_EVENT_ADDRESS + slot,
                            *row,
                            F(u64::try_from(address)
                                .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
                        )?;
                    }
                }
                if boolean_axis == BooleanTopologyAxisV1::BlockOrCall {
                    if chunk == 3 {
                        output.observe_v1(segment, FIX_BOOLEAN_LAST, *row, F::ONE)?;
                    } else {
                        output.observe_v1(segment, FIX_BOOLEAN_CONTINUE, *row, F::ONE)?;
                    }
                    output.observe_v1(segment, FIX_BOOLEAN_SCALE, *row, F(1_u64 << (chunk * 8)))?;
                    if chunk < 3 {
                        output.observe_v1(
                            segment,
                            FIX_BOOLEAN_NEXT_SCALE,
                            *row,
                            F(1_u64 << ((chunk + 1) * 8)),
                        )?;
                    }
                }
                *row = row
                    .checked_add(1)
                    .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            }
            operation_output.0
        }
        WordOperationV1::Add {
            inputs,
            arity,
            constant,
            output: operation_output,
            ..
        } => {
            let arity = usize::from(*arity);
            let selector = match arity {
                2 => FIX_ADD_ARITY_TWO,
                4 => FIX_ADD_ARITY_FOUR,
                _ => return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology),
            };
            output.observe_v1(segment, selector, *row, F::ONE)?;
            output.observe_v1(segment, FIX_ADD_CONSTANT, *row, F(u64::from(*constant)))?;
            for (slot, address) in inputs[..arity].iter().enumerate() {
                output.observe_v1(
                    segment,
                    FIX_EVENT_ADDRESS + slot,
                    *row,
                    F(u64::try_from(address.0)
                        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
                )?;
            }
            output.observe_v1(
                segment,
                FIX_EVENT_ADDRESS + arity,
                *row,
                F(u64::try_from(operation_output.0)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
            )?;
            *row = row
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            operation_output.0
        }
    };
    Ok(output_address)
}
fn word_memory_access_v1(
    circuit: &ZkX509Sha256WordCircuitV1,
    address: usize,
    is_write: bool,
) -> Result<WordMemoryAccessV1, ZkX509ShaFixedAlgebraicErrorV1> {
    let word = circuit
        .stark_words_v1()
        .get(address)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    Ok(WordMemoryAccessV1 {
        address: F(u64::try_from(address).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
        value: word.value,
        is_write: F(u64::from(is_write)),
    })
}
/// Reproduce the authoritative word-memory execution order used by
/// `build_sha_word_stark_base_v1`.
///
/// The circuit's native memory helper deliberately groups all definitions
/// before all reads. The committed word STARK instead flattens each local
/// row's events: definitions appear immediately before the operation that
/// consumes them, every operation appends its output write, and the eight
/// digest reads terminate the sequence. Fixed memory rows must follow that
/// committed order, while the address-sorted table is common to both orders.
fn interleaved_execution_memory_v1(
    circuit: &ZkX509Sha256WordCircuitV1,
) -> Result<Vec<WordMemoryAccessV1>, ZkX509ShaFixedAlgebraicErrorV1> {
    let expected_rows = circuit.stark_memory_v1().execution.len();
    let mut execution = Vec::new();
    execution
        .try_reserve_exact(expected_rows)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let mut word_cursor = 0_usize;
    let mut seen_outputs = BTreeSet::new();
    for operation in circuit.stark_operations_v1() {
        let output = match operation {
            WordOperationV1::Sigma { output, .. }
            | WordOperationV1::Choose { output, .. }
            | WordOperationV1::Majority { output, .. }
            | WordOperationV1::Add { output, .. } => output.0,
        };
        if !seen_outputs.insert(output) || output < word_cursor {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        while word_cursor < output {
            execution.push(word_memory_access_v1(circuit, word_cursor, true)?);
            word_cursor = word_cursor
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        }
        match operation {
            WordOperationV1::Sigma { input, .. } => {
                execution.push(word_memory_access_v1(circuit, input.0, false)?);
            }
            WordOperationV1::Choose { x, y, z, .. } | WordOperationV1::Majority { x, y, z, .. } => {
                for input in [x.0, y.0, z.0] {
                    execution.push(word_memory_access_v1(circuit, input, false)?);
                }
            }
            WordOperationV1::Add { inputs, arity, .. } => {
                let arity = usize::from(*arity);
                if !matches!(arity, 2 | 4) {
                    return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
                }
                for input in &inputs[..arity] {
                    execution.push(word_memory_access_v1(circuit, input.0, false)?);
                }
            }
        }
        execution.push(word_memory_access_v1(circuit, output, true)?);
        word_cursor = output
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    while word_cursor < circuit.stark_words_v1().len() {
        execution.push(word_memory_access_v1(circuit, word_cursor, true)?);
        word_cursor = word_cursor
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    for output in circuit.stark_output_words_v1() {
        execution.push(word_memory_access_v1(circuit, output.0, false)?);
    }
    if execution.len() != expected_rows {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(execution.len())
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    sorted.extend_from_slice(&execution);
    sorted.sort_by_key(|access| {
        (
            access.address.0,
            if access.is_write == F::ONE {
                0_u8
            } else {
                1_u8
            },
        )
    });
    if sorted != circuit.stark_memory_v1().sorted {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    Ok(execution)
}
fn emit_boolean_round_axis_atoms_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    compute_start: usize,
    block_count: usize,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    if block_count == 0 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    for block in 0..block_count {
        let block_start = block
            .checked_mul(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1)
            .and_then(|offset| compute_start.checked_add(offset))
            .and_then(|start| start.checked_add(SHA_ROUND_REGION_OFFSET_V1))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        for (selector, operation_offset) in [
            (FIX_CHOOSE, SHA_CHOOSE_ROUND_OFFSET_V1),
            (FIX_MAJORITY, SHA_MAJORITY_ROUND_OFFSET_V1),
        ] {
            for chunk in 0..4 {
                let first = block_start
                    .checked_add(operation_offset)
                    .and_then(|row| row.checked_add(chunk))
                    .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
                output.push_repeated_v1(
                    segment,
                    selector,
                    first,
                    SHA_ROUNDS_PER_BLOCK_V1,
                    SHA_ROUND_ROWS_V1,
                    F::ONE,
                )?;
                output.push_repeated_v1(
                    segment,
                    FIX_BOOLEAN_SCALE,
                    first,
                    SHA_ROUNDS_PER_BLOCK_V1,
                    SHA_ROUND_ROWS_V1,
                    F(1_u64 << (chunk * 8)),
                )?;
                if chunk == 0 {
                    output.push_repeated_v1(
                        segment,
                        FIX_BOOLEAN_FIRST,
                        first,
                        SHA_ROUNDS_PER_BLOCK_V1,
                        SHA_ROUND_ROWS_V1,
                        F::ONE,
                    )?;
                }
                if chunk == 3 {
                    output.push_repeated_v1(
                        segment,
                        FIX_BOOLEAN_LAST,
                        first,
                        SHA_ROUNDS_PER_BLOCK_V1,
                        SHA_ROUND_ROWS_V1,
                        F::ONE,
                    )?;
                } else {
                    output.push_repeated_v1(
                        segment,
                        FIX_BOOLEAN_CONTINUE,
                        first,
                        SHA_ROUNDS_PER_BLOCK_V1,
                        SHA_ROUND_ROWS_V1,
                        F::ONE,
                    )?;
                    output.push_repeated_v1(
                        segment,
                        FIX_BOOLEAN_NEXT_SCALE,
                        first,
                        SHA_ROUNDS_PER_BLOCK_V1,
                        SHA_ROUND_ROWS_V1,
                        F(1_u64 << ((chunk + 1) * 8)),
                    )?;
                }
            }
        }
    }
    Ok(())
}
fn emit_boolean_block_gap_axis_atoms_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    compute_start: usize,
    block_count: usize,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    if block_count < 14 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let atom_count_before = output.atom_count;
    let hull_count = block_count
        .checked_sub(1)
        .and_then(|blocks| blocks.checked_mul(SHA_BOOLEAN_BLOCK_LATTICE_STEPS_V1))
        .and_then(|steps| steps.checked_add(SHA_ROUNDS_PER_BLOCK_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let gap_count = block_count - 1;
    let round_start = compute_start
        .checked_add(SHA_ROUND_REGION_OFFSET_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let emit_lane = |output: &mut StructuralBuilderV1,
                     local_column: usize,
                     first: usize,
                     value: F|
     -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
        output.push_repeated_v1(
            segment,
            local_column,
            first,
            hull_count,
            SHA_ROUND_ROWS_V1,
            value,
        )?;
        let cancellation = F::ZERO.sub(value);
        for residue in 0..SHA_BOOLEAN_BLOCK_GAP_RESIDUES_V1 {
            let gap_first = first
                .checked_add(
                    SHA_ROUNDS_PER_BLOCK_V1
                        .checked_add(residue)
                        .and_then(|step| step.checked_mul(SHA_ROUND_ROWS_V1))
                        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                )
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            output.push_repeated_v1(
                segment,
                local_column,
                gap_first,
                gap_count,
                SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1,
                cancellation,
            )?;
        }
        Ok(())
    };
    for (selector, operation_offset) in [
        (FIX_CHOOSE, SHA_CHOOSE_ROUND_OFFSET_V1),
        (FIX_MAJORITY, SHA_MAJORITY_ROUND_OFFSET_V1),
    ] {
        for chunk in 0..4 {
            let first = round_start
                .checked_add(operation_offset)
                .and_then(|row| row.checked_add(chunk))
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            emit_lane(output, selector, first, F::ONE)?;
            emit_lane(output, FIX_BOOLEAN_SCALE, first, F(1_u64 << (chunk * 8)))?;
            if chunk == 0 {
                emit_lane(output, FIX_BOOLEAN_FIRST, first, F::ONE)?;
            }
            if chunk == 3 {
                emit_lane(output, FIX_BOOLEAN_LAST, first, F::ONE)?;
            } else {
                emit_lane(output, FIX_BOOLEAN_CONTINUE, first, F::ONE)?;
                emit_lane(
                    output,
                    FIX_BOOLEAN_NEXT_SCALE,
                    first,
                    F(1_u64 << ((chunk + 1) * 8)),
                )?;
            }
        }
    }
    let emitted_atoms = output
        .atom_count
        .checked_sub(atom_count_before)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    if emitted_atoms != SHA_BOOLEAN_BLOCK_GAP_ATOMS_PER_CALL_V1 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    Ok(())
}
fn operation_read_axis_atoms_per_call_v1(
    block_count: usize,
) -> Result<usize, ZkX509ShaFixedAlgebraicErrorV1> {
    let later_blocks = block_count
        .checked_sub(1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    SHA_OPERATION_AXIS_LATER_BLOCK_ATOMS_V1
        .checked_mul(later_blocks)
        .and_then(|atoms| atoms.checked_add(SHA_OPERATION_AXIS_FIRST_BLOCK_ATOMS_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)
}
fn emit_operation_read_axis_atoms_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    memory_start: usize,
    block_count: usize,
    execution: &[WordMemoryAccessV1],
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let expected_reads = SHA_OPERATION_READS_PER_BLOCK_V1
        .checked_mul(block_count)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let expected_rows = SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1
        .checked_mul(block_count)
        .and_then(|rows| rows.checked_add(FIXED_MEMORY_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let digest_start = execution
        .len()
        .checked_sub(DIGEST_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    if block_count == 0
        || execution.len() != expected_rows
        || execution[digest_start..]
            .iter()
            .any(|access| access.is_write != F::ZERO)
    {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let atom_count_before = output.atom_count;
    let column = output.combined_column_v1(segment, FIX_MEMORY_EXECUTION_ADDRESS)?;
    let column_u16 = u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let mut series = BTreeMap::<(usize, OperationReadPhaseV1, usize), NonzeroSeriesV1>::new();
    let mut read_index = 0_usize;
    for (memory_index, access) in execution[..digest_start].iter().copied().enumerate() {
        match access.is_write {
            F::ONE => continue,
            F::ZERO => {}
            _ => return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology),
        }
        if access.address == F::ZERO {
            read_index = read_index
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            continue;
        }
        let block = read_index / SHA_OPERATION_READS_PER_BLOCK_V1;
        let within_block = read_index % SHA_OPERATION_READS_PER_BLOCK_V1;
        if block >= block_count {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let (phase, slot) = if within_block < SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1 {
            (
                OperationReadPhaseV1::Expansion,
                within_block % SHA_OPERATION_EXPANSION_READ_SLOTS_V1,
            )
        } else if within_block
            < SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1 + SHA_OPERATION_ROUND_READS_PER_BLOCK_V1
        {
            (
                OperationReadPhaseV1::Round,
                (within_block - SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1)
                    % SHA_OPERATION_ROUND_READ_SLOTS_V1,
            )
        } else {
            (
                OperationReadPhaseV1::Final,
                (within_block
                    - SHA_OPERATION_EXPANSION_READS_PER_BLOCK_V1
                    - SHA_OPERATION_ROUND_READS_PER_BLOCK_V1)
                    % SHA_OPERATION_FINAL_READ_SLOTS_V1,
            )
        };
        let row = memory_start
            .checked_add(memory_index)
            .and_then(|row| u64::try_from(row).ok())
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        series
            .entry((block, phase, slot))
            .or_insert_with(NonzeroSeriesV1::empty_v1)
            .observe_v1(
                column_u16,
                NonzeroPointV1 {
                    row,
                    value: access.address,
                },
                &mut output.inner,
                &mut output.atom_count,
            )?;
        read_index = read_index
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    if read_index != expected_reads {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    for (_, mut series) in series {
        series.flush_v1(column_u16, &mut output.inner, &mut output.atom_count)?;
    }
    let emitted_atoms = output
        .atom_count
        .checked_sub(atom_count_before)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    if emitted_atoms != operation_read_axis_atoms_per_call_v1(block_count)? {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    Ok(())
}
fn sorted_memory_phase_key_v1(
    address: usize,
    block_count: usize,
) -> Result<(CallAxisBlockV1, SortedWordPhaseV1, usize), ZkX509ShaFixedAlgebraicErrorV1> {
    if address < INITIAL_LOCAL_ROWS_PER_CALL_V1 {
        return Ok((CallAxisBlockV1::Initial, SortedWordPhaseV1::Initial, 0));
    }
    let relative = address
        .checked_sub(INITIAL_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    let block = relative / SHA_WORDS_PER_BLOCK_V1;
    let position = relative % SHA_WORDS_PER_BLOCK_V1;
    if block >= block_count {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let (phase, slot) = if position < 16 {
        (SortedWordPhaseV1::Input, 0)
    } else if position < 160 {
        (SortedWordPhaseV1::Expansion, (position - 16) % 3)
    } else if position < 672 {
        (SortedWordPhaseV1::Round, (position - 160) % 8)
    } else {
        (SortedWordPhaseV1::Final, 0)
    };
    Ok((
        CallAxisBlockV1::Sha(
            u32::try_from(block).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
        ),
        phase,
        slot,
    ))
}
fn emit_execution_write_axis_atoms_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    memory_start: usize,
    block_count: usize,
    execution: &[WordMemoryAccessV1],
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let expected_words = SHA_WORDS_PER_BLOCK_V1
        .checked_mul(block_count)
        .and_then(|words| words.checked_add(INITIAL_LOCAL_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let expected_rows = SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1
        .checked_mul(block_count)
        .and_then(|rows| rows.checked_add(FIXED_MEMORY_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if block_count == 0 || execution.len() != expected_rows {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let address_column =
        u16::try_from(output.combined_column_v1(segment, FIX_MEMORY_EXECUTION_ADDRESS)?)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let write_column =
        u16::try_from(output.combined_column_v1(segment, FIX_MEMORY_EXECUTION_WRITE)?)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let mut seen_writes = Vec::new();
    seen_writes
        .try_reserve_exact(expected_words)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    seen_writes.resize(expected_words, false);
    let mut series =
        BTreeMap::<(u16, CallAxisBlockV1, SortedWordPhaseV1, usize), NonzeroSeriesV1>::new();
    for (memory_index, access) in execution.iter().copied().enumerate() {
        match access.is_write {
            F::ZERO => continue,
            F::ONE => {}
            _ => return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology),
        }
        let address = usize::try_from(access.address.0)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let seen = seen_writes
            .get_mut(address)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        if core::mem::replace(seen, true) {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let (block, phase, slot) = sorted_memory_phase_key_v1(address, block_count)?;
        let row = memory_start
            .checked_add(memory_index)
            .and_then(|row| u64::try_from(row).ok())
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        for (column, value) in [(address_column, access.address), (write_column, F::ONE)] {
            if value == F::ZERO {
                continue;
            }
            series
                .entry((column, block, phase, slot))
                .or_insert_with(NonzeroSeriesV1::empty_v1)
                .observe_v1(
                    column,
                    NonzeroPointV1 { row, value },
                    &mut output.inner,
                    &mut output.atom_count,
                )?;
        }
    }
    if seen_writes.iter().any(|seen| !*seen) {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    for ((column, _, _, _), mut series) in series {
        series.flush_v1(column, &mut output.inner, &mut output.atom_count)?;
    }
    Ok(())
}
fn emit_sorted_memory_phase_axis_atoms_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    memory_start: usize,
    block_count: usize,
    execution: &[WordMemoryAccessV1],
    sorted: &[WordMemoryAccessV1],
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let expected_words = SHA_WORDS_PER_BLOCK_V1
        .checked_mul(block_count)
        .and_then(|words| words.checked_add(INITIAL_LOCAL_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let expected_rows = SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1
        .checked_mul(block_count)
        .and_then(|rows| rows.checked_add(FIXED_MEMORY_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if block_count == 0 || execution.len() != expected_rows || sorted.len() != expected_rows {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let mut execution_counts = Vec::new();
    execution_counts
        .try_reserve_exact(expected_words)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    execution_counts.resize(expected_words, [0_usize; 2]);
    for access in execution.iter().copied() {
        let address = usize::try_from(access.address.0)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let write = match access.is_write {
            F::ZERO => 0,
            F::ONE => 1,
            _ => return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology),
        };
        let count = execution_counts
            .get_mut(address)
            .and_then(|counts| counts.get_mut(write))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        *count = count
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    if execution_counts.iter().any(|counts| counts[1] != 1) {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let combined_column = |local_column| {
        output
            .combined_column_v1(segment, local_column)
            .and_then(|column| {
                u16::try_from(column).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)
            })
    };
    let sorted_address_column = combined_column(FIX_MEMORY_SORTED_ADDRESS)?;
    let sorted_write_column = combined_column(FIX_MEMORY_SORTED_WRITE)?;
    let same_next_column = combined_column(FIX_MEMORY_SAME_NEXT)?;
    let new_next_column = combined_column(FIX_MEMORY_NEW_NEXT)?;
    let atom_count_before = output.atom_count;
    let mut series =
        BTreeMap::<(u16, CallAxisBlockV1, SortedWordPhaseV1, usize, usize), NonzeroSeriesV1>::new();
    let mut prior_address = None;
    let mut occurrence = 0_usize;
    let mut address_zero_rows = 0_usize;
    let mut consumed_rows = 0_usize;
    for (index, access) in sorted.iter().copied().enumerate() {
        let address = usize::try_from(access.address.0)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if address >= expected_words || F::canonical(access.address.0).is_none() {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let write = match access.is_write {
            F::ZERO => 0,
            F::ONE => 1,
            _ => return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology),
        };
        let remaining = execution_counts
            .get_mut(address)
            .and_then(|counts| counts.get_mut(write))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        *remaining = remaining
            .checked_sub(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        if prior_address == Some(address) {
            occurrence = occurrence
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            if access.is_write != F::ZERO {
                return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
            }
        } else {
            if prior_address.map_or(address != 0, |prior| address != prior + 1)
                || access.is_write != F::ONE
            {
                return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
            }
            prior_address = Some(address);
            occurrence = 0;
        }
        if address == 0 {
            address_zero_rows = address_zero_rows
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        }
        let same_next = sorted
            .get(index + 1)
            .is_some_and(|next| next.address == access.address);
        let new_next = index + 1 < sorted.len() && !same_next;
        let (block, phase, slot) = sorted_memory_phase_key_v1(address, block_count)?;
        let row = memory_start
            .checked_add(index)
            .and_then(|row| u64::try_from(row).ok())
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        for (column, value) in [
            (sorted_address_column, access.address),
            (sorted_write_column, access.is_write),
            (same_next_column, F(u64::from(same_next))),
            (new_next_column, F(u64::from(new_next))),
        ] {
            if value == F::ZERO {
                continue;
            }
            series
                .entry((column, block, phase, slot, occurrence))
                .or_insert_with(NonzeroSeriesV1::empty_v1)
                .observe_v1(
                    column,
                    NonzeroPointV1 { row, value },
                    &mut output.inner,
                    &mut output.atom_count,
                )?;
        }
        consumed_rows = consumed_rows
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    if consumed_rows != expected_rows
        || prior_address != Some(expected_words - 1)
        || address_zero_rows != 7
        || execution_counts
            .iter()
            .any(|counts| counts.iter().any(|count| *count != 0))
    {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    for ((column, _, _, _, _), mut series) in series {
        series.flush_v1(column, &mut output.inner, &mut output.atom_count)?;
    }
    let emitted_atoms = output
        .atom_count
        .checked_sub(atom_count_before)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    let expected_atoms = SHA_SORTED_PHASE_AXIS_ATOMS_PER_BLOCK_V1
        .checked_mul(block_count)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if emitted_atoms != expected_atoms {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    Ok(())
}
fn emit_rfc_length_events_v1(
    output: &mut StructuralBuilderV1,
    segment: usize,
    end: usize,
    consumer: ZkX509ShaRfcConsumerChannelsV1,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let Some(length_channel) = consumer.length_channel else {
        return Ok(());
    };
    for pair in 0..4 {
        let row = end
            .checked_sub(4)
            .and_then(|start| start.checked_add(pair))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        output.observe_v1(segment, SHA_FIXED_RFC_LENGTH_PAIR_V1, row, F::ONE)?;
        output.observe_v1(
            segment,
            SHA_FIXED_RFC_LENGTH_PAIR_INDEX_V1,
            row,
            F(u64::try_from(pair).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
        )?;
        for stream in 0..2 {
            let offset = pair * 2 + stream;
            let base = SHA_FIXED_RFC_STREAMS_V1 + stream * SHA_FIXED_RFC_STREAM_STRIDE_V1;
            output.observe_v1(
                segment,
                base + SHA_FIXED_RFC_LENGTH_HIGH_VALUE_V1,
                row,
                F(u64::from(offset == 6)),
            )?;
            output.observe_v1(
                segment,
                base + SHA_FIXED_RFC_LENGTH_LOW_VALUE_V1,
                row,
                F(u64::from(offset == 7)),
            )?;
            output.observe_v1(
                segment,
                base + SHA_FIXED_RFC_ROLE_V1,
                row,
                F(consumer.role as u64),
            )?;
            output.observe_v1(
                segment,
                base + SHA_FIXED_RFC_CHANNEL_V1,
                row,
                F(u64::from(length_channel)),
            )?;
            output.observe_v1(
                segment,
                base + SHA_FIXED_RFC_OFFSET_V1,
                row,
                F(u64::try_from(offset).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
            )?;
        }
    }
    Ok(())
}
fn emit_call_topology_v1(
    output: &mut StructuralBuilderV1,
    manifest: ZkX509ShaCallManifestV1,
    shape: ZkX509ShaCallPublicShapeV1,
    repeat_across_calls: bool,
    boolean_axis: BooleanTopologyAxisV1,
    operation_read_phase_axis: bool,
    sorted_memory_phase_axis: bool,
) -> Result<(), ZkX509ShaFixedAlgebraicErrorV1> {
    let global_start = manifest.first_logical_row;
    let segment = global_start / ZK_X509_SHA_SEGMENT_ROWS_V1;
    let start = global_start % ZK_X509_SHA_SEGMENT_ROWS_V1;
    if segment >= ZK_X509_SHA_SEGMENT_COUNT_V1 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let mut message = Vec::new();
    message
        .try_reserve_exact(manifest.maximum_message_bytes)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    message.resize(manifest.maximum_message_bytes, 0_u8);
    let digest = Sha256::digest(&message);
    let circuit = build_sha256_word_circuit_v1(&message)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    drop(message);
    let input_words = circuit.stark_input_words_v1();
    if input_words.len() != manifest.maximum_blocks * 16 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let mut input_indices = Vec::new();
    input_indices
        .try_reserve_exact(circuit.stark_words_v1().len())
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    input_indices.resize(circuit.stark_words_v1().len(), None);
    for (index, word) in input_words.iter().copied().enumerate() {
        let slot = input_indices
            .get_mut(word.0)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        if slot.replace(index).is_some() {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
    }
    let local_rows = manifest
        .maximum_blocks
        .checked_mul(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1)
        .and_then(|rows| rows.checked_add(INITIAL_LOCAL_ROWS_PER_CALL_V1))
        .and_then(|rows| rows.checked_add(DIGEST_LOCAL_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let memory_rows = manifest
        .maximum_blocks
        .checked_mul(SHA_WORD_CAPACITY_MEMORY_ROWS_PER_BLOCK_V1)
        .and_then(|rows| rows.checked_add(FIXED_MEMORY_ROWS_PER_CALL_V1))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let execution = interleaved_execution_memory_v1(&circuit)?;
    let sorted = &circuit.stark_memory_v1().sorted;
    if execution.len() != memory_rows || sorted.len() != memory_rows {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let consumer = rfc_consumer_v1(manifest, shape)?;
    emit_common_call_atoms_v1(
        output,
        manifest,
        segment,
        start,
        local_rows,
        memory_rows,
        consumer,
    )?;
    let compute_start = start
        .checked_add(INITIAL_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let compute_end = compute_start
        .checked_add(
            manifest
                .maximum_blocks
                .checked_mul(SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
        )
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    output.begin_repeat_zone_v1(
        segment,
        compute_start,
        compute_end,
        SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1,
        [true; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1],
        if repeat_across_calls {
            RepeatZoneAxisV1::Calls {
                family: REPEAT_FAMILY_COMPUTE_V1,
            }
        } else {
            RepeatZoneAxisV1::Blocks
        },
    )?;
    match boolean_axis {
        BooleanTopologyAxisV1::BlockOrCall => {}
        BooleanTopologyAxisV1::Round => {
            emit_boolean_round_axis_atoms_v1(
                output,
                segment,
                compute_start,
                manifest.maximum_blocks,
            )?;
        }
        BooleanTopologyAxisV1::BlockGap => {
            emit_boolean_block_gap_axis_atoms_v1(
                output,
                segment,
                compute_start,
                manifest.maximum_blocks,
            )?;
        }
    }
    let mut row = start;
    let mut word_cursor = 0_usize;
    let mut seen_outputs = BTreeSet::new();
    for operation in circuit.stark_operations_v1() {
        let operation_output = match operation {
            WordOperationV1::Sigma { output, .. }
            | WordOperationV1::Choose { output, .. }
            | WordOperationV1::Majority { output, .. }
            | WordOperationV1::Add { output, .. } => output.0,
        };
        if !seen_outputs.insert(operation_output) || operation_output < word_cursor {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        while word_cursor < operation_output {
            emit_word_row_v1(
                output,
                &circuit,
                &input_indices,
                manifest,
                consumer,
                segment,
                row,
                word_cursor,
            )?;
            word_cursor = word_cursor
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            row = row
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        }
        if emit_operation_v1(output, segment, &mut row, operation, boolean_axis)?
            != operation_output
        {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        word_cursor = operation_output
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    while word_cursor < circuit.stark_words_v1().len() {
        emit_word_row_v1(
            output,
            &circuit,
            &input_indices,
            manifest,
            consumer,
            segment,
            row,
            word_cursor,
        )?;
        word_cursor = word_cursor
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        row = row
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    for (digest_index, output_word) in circuit.stark_output_words_v1().into_iter().enumerate() {
        output.observe_v1(segment, FIX_DIGEST, row, F::ONE)?;
        output.observe_v1(
            segment,
            FIX_DIGEST_EXPECTED,
            row,
            F(u64::from(u32::from_be_bytes(
                digest[digest_index * 4..digest_index * 4 + 4]
                    .try_into()
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Topology)?,
            ))),
        )?;
        output.observe_v1(
            segment,
            FIX_EVENT_ADDRESS,
            row,
            F(u64::try_from(output_word.0)
                .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?),
        )?;
        output.observe_v1(
            segment,
            SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1,
            row,
            F(
                u64::try_from(digest_index)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
            ),
        )?;
        row = row
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    if row != start + local_rows {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    output.finish_repeat_zone_v1()?;
    let word_count = circuit.stark_words_v1().len();
    let words_per_block = word_count
        .checked_sub(INITIAL_LOCAL_ROWS_PER_CALL_V1)
        .filter(|words| *words % manifest.maximum_blocks == 0)
        .map(|words| words / manifest.maximum_blocks)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    if words_per_block != SHA_WORDS_PER_BLOCK_V1 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let memory_start = start
        .checked_add(local_rows)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let digest_start = memory_rows
        .checked_sub(DIGEST_LOCAL_ROWS_PER_CALL_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    emit_execution_write_axis_atoms_v1(
        output,
        segment,
        memory_start,
        manifest.maximum_blocks,
        &execution,
    )?;
    if operation_read_phase_axis {
        emit_operation_read_axis_atoms_v1(
            output,
            segment,
            memory_start,
            manifest.maximum_blocks,
            &execution,
        )?;
    }
    if sorted_memory_phase_axis {
        emit_sorted_memory_phase_axis_atoms_v1(
            output,
            segment,
            memory_start,
            manifest.maximum_blocks,
            &execution,
            sorted,
        )?;
    }
    let mut prior_sorted_address = None;
    let mut sorted_occurrence = 0_usize;
    let mut operation_read_index = 0_usize;
    for (memory_index, (execution, sorted)) in execution.iter().zip(sorted).enumerate() {
        let is_operation_read = memory_index < digest_start && execution.is_write == F::ZERO;
        if execution.is_write != F::ZERO && execution.is_write != F::ONE {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        if is_operation_read {
            let block = operation_read_index / SHA_OPERATION_READS_PER_BLOCK_V1;
            let position = operation_read_index % SHA_OPERATION_READS_PER_BLOCK_V1;
            if block >= manifest.maximum_blocks {
                return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
            }
            if !operation_read_phase_axis {
                output.observe_family_keyed_v1(
                    segment,
                    FIX_MEMORY_EXECUTION_ADDRESS,
                    row,
                    REPEAT_FAMILY_EXECUTION_READ_V1,
                    CallAxisBlockV1::Sha(
                        u32::try_from(block)
                            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                    ),
                    u32::try_from(position)
                        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                    CALL_AXIS_UNKEYED_OCCURRENCE_V1,
                    execution.address,
                )?;
            }
            operation_read_index = operation_read_index
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        } else if execution.is_write == F::ONE {
            if memory_index >= digest_start {
                return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
            }
        } else {
            if memory_index < digest_start {
                return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
            }
            output.observe_v1(
                segment,
                FIX_MEMORY_EXECUTION_ADDRESS,
                row,
                execution.address,
            )?;
        }
        if !sorted_memory_phase_axis {
            let sorted_address = usize::try_from(sorted.address.0)
                .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            if prior_sorted_address == Some(sorted_address) {
                sorted_occurrence = sorted_occurrence
                    .checked_add(1)
                    .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            } else {
                prior_sorted_address = Some(sorted_address);
                sorted_occurrence = 0;
            }
            let same_next = circuit
                .stark_memory_v1()
                .sorted
                .get(memory_index + 1)
                .is_some_and(|next| next.address == sorted.address);
            if let Some(relative_address) =
                sorted_address.checked_sub(INITIAL_LOCAL_ROWS_PER_CALL_V1)
            {
                let block = relative_address / words_per_block;
                let position = relative_address % words_per_block;
                if block >= manifest.maximum_blocks {
                    return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
                }
                let word_position = u32::try_from(position)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
                let block = CallAxisBlockV1::Sha(
                    u32::try_from(block).map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?,
                );
                let occurrence = u32::try_from(sorted_occurrence)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
                output.observe_keyed_v1(
                    segment,
                    FIX_MEMORY_SORTED_ADDRESS,
                    row,
                    block,
                    word_position,
                    occurrence,
                    sorted.address,
                )?;
                output.observe_keyed_v1(
                    segment,
                    FIX_MEMORY_SORTED_WRITE,
                    row,
                    block,
                    word_position,
                    occurrence,
                    sorted.is_write,
                )?;
                if memory_index + 1 < memory_rows {
                    output.observe_keyed_v1(
                        segment,
                        if same_next {
                            FIX_MEMORY_SAME_NEXT
                        } else {
                            FIX_MEMORY_NEW_NEXT
                        },
                        row,
                        block,
                        word_position,
                        if same_next { occurrence } else { u32::MAX },
                        F::ONE,
                    )?;
                }
            } else {
                let word_position = u32::try_from(sorted_address)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
                let occurrence = u32::try_from(sorted_occurrence)
                    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
                output.observe_keyed_v1(
                    segment,
                    FIX_MEMORY_SORTED_ADDRESS,
                    row,
                    CallAxisBlockV1::Initial,
                    word_position,
                    occurrence,
                    sorted.address,
                )?;
                output.observe_keyed_v1(
                    segment,
                    FIX_MEMORY_SORTED_WRITE,
                    row,
                    CallAxisBlockV1::Initial,
                    word_position,
                    occurrence,
                    sorted.is_write,
                )?;
                if memory_index + 1 < memory_rows {
                    output.observe_keyed_v1(
                        segment,
                        if same_next {
                            FIX_MEMORY_SAME_NEXT
                        } else {
                            FIX_MEMORY_NEW_NEXT
                        },
                        row,
                        CallAxisBlockV1::Initial,
                        word_position,
                        if same_next { occurrence } else { u32::MAX },
                        F::ONE,
                    )?;
                }
            }
        }
        row = row
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    }
    let expected_operation_reads = SHA_OPERATION_READS_PER_BLOCK_V1
        .checked_mul(manifest.maximum_blocks)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if operation_read_index != expected_operation_reads {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let end = start + manifest.maximum_logical_rows();
    if row != end {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    if let Some(consumer) = consumer {
        emit_rfc_length_events_v1(output, segment, end, consumer)?;
    }
    Ok(())
}
fn calls_share_repeat_geometry_v1(
    left: ZkX509ShaCallManifestV1,
    right: ZkX509ShaCallManifestV1,
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<bool, ZkX509ShaFixedAlgebraicErrorV1> {
    let left_end = left
        .first_logical_row
        .checked_add(left.maximum_logical_rows())
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    Ok(left_end == right.first_logical_row
        && left.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1
            == right.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1
        && left.maximum_message_bytes == right.maximum_message_bytes
        && left.maximum_blocks == right.maximum_blocks
        && left.maximum_local_rows == right.maximum_local_rows
        && left.maximum_memory_rows == right.maximum_memory_rows
        && exact_message_length_v1(left.role) == exact_message_length_v1(right.role)
        && rfc_consumer_v1(left, shape)? == rfc_consumer_v1(right, shape)?)
}
fn transpose_run_to_call_axis_v1(
    call_count: usize,
    block_count: usize,
) -> Result<bool, ZkX509ShaFixedAlgebraicErrorV1> {
    if call_count == 0 || block_count == 0 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    // The two axes retain respectively one exact series per call or per
    // block. Strict comparison makes the lower atom bound canonical, with
    // the established row/block axis winning ties.
    Ok(call_count > block_count)
}
fn plan_boolean_topology_axis_v1(
    call_count: usize,
    block_count: usize,
) -> Result<BooleanTopologyAxisV1, ZkX509ShaFixedAlgebraicErrorV1> {
    if call_count == 0 || block_count == 0 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let mut best_atoms = SHA_BOOLEAN_BLOCK_OR_CALL_AXIS_ATOMS_V1
        .checked_mul(call_count.min(block_count))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let mut best_axis = BooleanTopologyAxisV1::BlockOrCall;
    let round_atoms = SHA_BOOLEAN_ROUND_AXIS_ATOMS_PER_BLOCK_V1
        .checked_mul(call_count)
        .and_then(|atoms| atoms.checked_mul(block_count))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if round_atoms < best_atoms {
        best_atoms = round_atoms;
        best_axis = BooleanTopologyAxisV1::Round;
    }
    if block_count > 1 {
        let block_gap_atoms = SHA_BOOLEAN_BLOCK_GAP_ATOMS_PER_CALL_V1
            .checked_mul(call_count)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if block_gap_atoms < best_atoms {
            best_axis = BooleanTopologyAxisV1::BlockGap;
        }
    }
    // Strict comparisons make the exact lower atom count canonical. The
    // established block/call axis wins its ties; the round axis wins the
    // 13-block tie with the additive block-gap axis.
    Ok(best_axis)
}
fn transpose_operation_reads_to_phase_axis_v1(
    call_count: usize,
    block_count: usize,
    repeat_across_calls: bool,
) -> Result<bool, ZkX509ShaFixedAlgebraicErrorV1> {
    if call_count == 0 || block_count == 0 || repeat_across_calls != (call_count > block_count) {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let phase_axis_atoms = operation_read_axis_atoms_per_call_v1(block_count)?
        .checked_mul(call_count)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let existing_axis_atoms = if repeat_across_calls {
        SHA_OPERATION_READS_PER_BLOCK_V1
            .checked_mul(block_count)
            .and_then(|atoms| {
                atoms.checked_sub(
                    SHA_OPERATION_READS_PER_BLOCK_V1 - SHA_OPERATION_FIRST_BLOCK_NONZERO_READS_V1,
                )
            })
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?
    } else {
        let per_call = if block_count == 1 {
            SHA_OPERATION_FIRST_BLOCK_NONZERO_READS_V1
        } else {
            SHA_OPERATION_READS_PER_BLOCK_V1
        };
        per_call
            .checked_mul(call_count)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?
    };
    // The exact lower atom count is canonical. Preserve the established
    // block/call-axis representation on a tie.
    Ok(phase_axis_atoms < existing_axis_atoms)
}
fn transpose_sorted_memory_to_phase_axis_v1(
    call_count: usize,
    block_count: usize,
    repeat_across_calls: bool,
) -> Result<bool, ZkX509ShaFixedAlgebraicErrorV1> {
    if call_count == 0 || block_count == 0 || repeat_across_calls != (call_count > block_count) {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let phase_axis_atoms = SHA_SORTED_PHASE_AXIS_ATOMS_PER_BLOCK_V1
        .checked_mul(block_count)
        .and_then(|atoms| atoms.checked_mul(call_count))
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let existing_axis_atoms = if repeat_across_calls {
        SHA_SORTED_CALL_AXIS_ATOMS_PER_BLOCK_V1
            .checked_mul(block_count)
            .and_then(|atoms| atoms.checked_add(SHA_SORTED_CALL_AXIS_FIXED_ATOMS_V1))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?
    } else {
        SHA_SORTED_CALL_AXIS_ATOMS_PER_BLOCK_V1
            .checked_add(SHA_SORTED_CALL_AXIS_FIXED_ATOMS_V1)
            .and_then(|atoms| atoms.checked_mul(call_count))
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?
    };
    // The exact lower atom count is canonical. Preserve the established
    // block/call-axis representation on a tie.
    Ok(phase_axis_atoms < existing_axis_atoms)
}
/// Digest of the stable compiler algorithm descriptor.
#[cfg(test)]
pub fn zk_x509_sha_fixed_algebraic_compiler_descriptor_digest_v1()
-> Result<PrivacyOuterDigestV1, ZkX509ShaFixedAlgebraicErrorV1> {
    privacy_outer_digest_frame_v1(
        ZK_X509_FIXED_DIGEST_CONTEXT_V1,
        SHA_COMPILER_DESCRIPTOR_DIGEST_DOMAIN_V1,
        b"sha-fixed-algebraic-compiler",
        0,
        0,
        0,
        &[ZK_X509_SHA_FIXED_ALGEBRAIC_COMPILER_DESCRIPTOR_V1],
    )
    .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Topology)
}
/// Typed composition of the four independently committed SHA segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509ShaFixedAlgebraicScheduleV1 {
    children: [ZkX509FixedAlgebraicScheduleV1; ZK_X509_SHA_SEGMENT_COUNT_V1],
    descriptor_digest: PrivacyOuterDigestV1,
}
impl ZkX509ShaFixedAlgebraicScheduleV1 {
    fn new_v1(
        shape: ZkX509ShaCallPublicShapeV1,
        children: [ZkX509FixedAlgebraicScheduleV1; ZK_X509_SHA_SEGMENT_COUNT_V1],
    ) -> Result<Self, ZkX509ShaFixedAlgebraicErrorV1> {
        if shape.disclosed_attributes > 4 {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let domain = children
            .first()
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?
            .domain_v1();
        if children
            .iter()
            .zip(SHA_FIXED_ALGEBRAIC_CHILD_ATOM_COUNTS_V1)
            .any(|(child, atom_count)| {
                child.domain_v1() != domain
                    || usize::from(child.width_v1()) != ZK_X509_SHA_BATCH_FIXED_WIDTH_V1
                    || child.atoms_v1().len() != atom_count
            })
        {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
        let disclosed_attributes = [u8::try_from(shape.disclosed_attributes)
            .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Topology)?];
        let mut encoded_widths = [0_u8; 2 * ZK_X509_SHA_SEGMENT_COUNT_V1];
        let mut child_digests = [0_u8; 48 * ZK_X509_SHA_SEGMENT_COUNT_V1];
        for (index, child) in children.iter().enumerate() {
            encoded_widths[index * 2..index * 2 + 2]
                .copy_from_slice(&child.width_v1().to_be_bytes());
            child_digests[index * 48..index * 48 + 48]
                .copy_from_slice(&child.descriptor_digest_v1().to_bytes());
        }
        let descriptor_digest = privacy_outer_digest_frame_v1(
            ZK_X509_FIXED_DIGEST_CONTEXT_V1,
            SHA_COMPOSITE_DESCRIPTOR_DIGEST_DOMAIN_V1,
            b"sha-fixed-algebraic-composite",
            0,
            0,
            0,
            &[
                ZK_X509_SHA_FIXED_ALGEBRAIC_COMPILER_DESCRIPTOR_V1,
                &disclosed_attributes,
                &encoded_widths,
                &child_digests,
            ],
        )
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
        Ok(Self {
            children,
            descriptor_digest,
        })
    }
    /// Common algebraic domain shared by all four segments.
    #[cfg(test)]
    pub(crate) fn domain_v1(&self) -> ZkX509FixedAlgebraicDomainV1 {
        self.children[0].domain_v1()
    }
    /// Digest binding compiler semantics and all ordered child descriptors.
    pub(crate) const fn descriptor_digest_v1(&self) -> PrivacyOuterDigestV1 {
        self.descriptor_digest
    }
    /// Fail closed unless the compiled profile pins this exact composite.
    #[cfg(test)]
    pub(crate) fn verify_descriptor_digest_v1(
        &self,
        expected: &PrivacyOuterDigestV1,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if self.descriptor_digest != *expected {
            return Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch);
        }
        Ok(())
    }
    /// Borrow the independently capped segment schedules in physical order.
    #[cfg(test)]
    pub(crate) const fn children_v1(
        &self,
    ) -> &[ZkX509FixedAlgebraicScheduleV1; ZK_X509_SHA_SEGMENT_COUNT_V1] {
        &self.children
    }
    /// Exact total across the four independently capped atom collections.
    #[cfg(test)]
    pub(crate) fn atom_count_v1(&self) -> usize {
        self.children
            .iter()
            .map(|child| child.atoms_v1().len())
            .sum()
    }
    /// Evaluate one combined native row without constructing a native matrix.
    #[cfg(test)]
    pub(crate) fn native_row_v1(
        &self,
        row: u64,
        output: &mut [F],
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if output.len() != ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        for (segment, child) in self.children.iter().enumerate() {
            let start = segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
            child.native_row_v1(
                row,
                &mut output[start..start + ZK_X509_SHA_BATCH_FIXED_WIDTH_V1],
            )?;
        }
        Ok(())
    }
    /// Evaluate the same ordered child fixed polynomials at the DEEP point.
    /// Each child enforces its public work bound; only one child table is live.
    pub(crate) fn evaluate_extension_point_v1(
        &self,
        point: E,
    ) -> Result<Vec<E>, ZkX509FixedAlgebraicErrorV1> {
        let mut combined = Vec::new();
        combined
            .try_reserve_exact(ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for child in &self.children {
            let row = child.evaluate_extension_point_v1(point)?;
            if row.len() != usize::from(child.width_v1()) {
                return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
            }
            combined.extend(row);
        }
        if combined.len() != ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(combined)
    }
    #[cfg(test)]
    /// Evaluate and concatenate all four child openings in physical order.
    pub(crate) fn evaluate_query_indices_v1(
        &self,
        query_indices: &[u64],
    ) -> Result<ZkX509FixedAlgebraicOpeningsV1, ZkX509FixedAlgebraicErrorV1> {
        let mut parts = Vec::new();
        parts
            .try_reserve_exact(self.children.len())
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for child in &self.children {
            parts.push(child.evaluate_query_indices_v1(query_indices)?);
        }
        ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(self.descriptor_digest, &parts)
    }
    #[cfg(test)]
    fn atoms_v1(&self) -> Vec<ZkX509FixedAlgebraicAtomV1> {
        let mut atoms = Vec::with_capacity(self.atom_count_v1());
        for (segment, child) in self.children.iter().enumerate() {
            let column_offset = u16::try_from(segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1)
                .expect("combined SHA width fits u16");
            atoms.extend(child.atoms_v1().iter().copied().map(|atom| match atom {
                ZkX509FixedAlgebraicAtomV1::Affine {
                    column,
                    start,
                    end,
                    start_value,
                    step,
                } => ZkX509FixedAlgebraicAtomV1::Affine {
                    column: column_offset + column,
                    start,
                    end,
                    start_value,
                    step,
                },
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column,
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                } => ZkX509FixedAlgebraicAtomV1::Repeated {
                    column: column_offset + column,
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                },
                ZkX509FixedAlgebraicAtomV1::Sparse { column, row, value } => {
                    ZkX509FixedAlgebraicAtomV1::Sparse {
                        column: column_offset + column,
                        row,
                        value,
                    }
                }
            }));
        }
        atoms
    }
}
fn compile_sha_fixed_segment_v1(
    domain: ZkX509FixedAlgebraicDomainV1,
    shape: ZkX509ShaCallPublicShapeV1,
    segment: usize,
    calls: &[ZkX509ShaCallManifestV1],
) -> Result<ZkX509FixedAlgebraicScheduleV1, ZkX509ShaFixedAlgebraicErrorV1> {
    let segment_start = segment
        .checked_mul(ZK_X509_SHA_SEGMENT_ROWS_V1)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let expected_end = segment_start
        .checked_add(
            *ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1
                .get(segment)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?,
        )
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    let first_call = calls
        .first()
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    let last_call = calls
        .last()
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    let actual_end = last_call
        .first_logical_row
        .checked_add(last_call.maximum_logical_rows())
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    if first_call.first_logical_row != segment_start
        || actual_end != expected_end
        || calls
            .iter()
            .any(|call| call.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1 != segment)
        || calls.windows(2).any(|pair| {
            pair[0]
                .first_logical_row
                .checked_add(pair[0].maximum_logical_rows())
                != Some(pair[1].first_logical_row)
        })
    {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let mut output = StructuralBuilderV1::new_v1(domain, segment)?;
    let mut first = 0_usize;
    while first < calls.len() {
        let mut end = first
            .checked_add(1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        while end < calls.len()
            && calls_share_repeat_geometry_v1(calls[end - 1], calls[end], shape)?
        {
            end = end
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        }
        let run = &calls[first..end];
        let block_count = run
            .first()
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?
            .maximum_blocks;
        let repeat_across_calls = transpose_run_to_call_axis_v1(run.len(), block_count)?;
        let boolean_axis = plan_boolean_topology_axis_v1(run.len(), block_count)?;
        let operation_read_phase_axis = transpose_operation_reads_to_phase_axis_v1(
            run.len(),
            block_count,
            repeat_across_calls,
        )?;
        let sorted_memory_phase_axis =
            transpose_sorted_memory_to_phase_axis_v1(run.len(), block_count, repeat_across_calls)?;
        if repeat_across_calls {
            output.begin_call_axis_group_v1()?;
        }
        for manifest in run.iter().copied() {
            emit_call_topology_v1(
                &mut output,
                manifest,
                shape,
                repeat_across_calls,
                boolean_axis,
                operation_read_phase_axis,
                sorted_memory_phase_axis,
            )?;
        }
        if repeat_across_calls {
            output.finish_call_axis_group_v1()?;
        }
        first = end;
    }
    output.flush_keyed_v1()?;
    let active = ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[segment];
    output.observe_v1(segment, ZK_X509_SHA_FIXED_SEGMENT_FIRST_V1, 0, F::ONE)?;
    output.observe_v1(
        segment,
        ZK_X509_SHA_FIXED_SEGMENT_LAST_V1,
        active - 1,
        F::ONE,
    )?;
    output.push_constant_v1(
        segment,
        ZK_X509_SHA_FIXED_PHYSICAL_PADDING_V1,
        active,
        ZK_X509_SHA_SEGMENT_ROWS_V1,
        F::ONE,
    )?;
    output.finish_v1()
}
fn compile_sha_fixed_algebraic_children_v1(
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<
    [ZkX509FixedAlgebraicScheduleV1; ZK_X509_SHA_SEGMENT_COUNT_V1],
    ZkX509ShaFixedAlgebraicErrorV1,
> {
    if shape.disclosed_attributes > 4 {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
        19,
        ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
        F(GOLDILOCKS_GENERATOR_V1),
    )?;
    let schedule = ZkX509ShaCallScheduleV1::new(shape)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    let mut calls = schedule.calls().to_vec();
    let mut unique_starts = BTreeSet::new();
    for manifest in calls.iter().copied() {
        let start = manifest.first_logical_row;
        let segment = start / ZK_X509_SHA_SEGMENT_ROWS_V1;
        let segment_start = segment
            .checked_mul(ZK_X509_SHA_SEGMENT_ROWS_V1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let end = start
            .checked_add(manifest.maximum_logical_rows())
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        let segment_end = segment_start
            .checked_add(ZK_X509_SHA_SEGMENT_ROWS_V1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if segment >= ZK_X509_SHA_SEGMENT_COUNT_V1
            || !unique_starts.insert(start)
            || start < segment_start
            || end > segment_end
        {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
    }
    calls.sort_unstable_by_key(|manifest| manifest.first_logical_row);
    for adjacent in calls.windows(2) {
        let prior = adjacent[0];
        let next = adjacent[1];
        let prior_end = prior
            .first_logical_row
            .checked_add(prior.maximum_logical_rows())
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        if prior.first_logical_row >= next.first_logical_row || prior_end > next.first_logical_row {
            return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
        }
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(ZK_X509_SHA_SEGMENT_COUNT_V1)
        .map_err(|_| ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
    for segment in 0..ZK_X509_SHA_SEGMENT_COUNT_V1 {
        let first = calls
            .partition_point(|call| call.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1 < segment);
        let end = calls.partition_point(|call| {
            call.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1 <= segment
        });
        children.push(compile_sha_fixed_segment_v1(
            domain,
            shape,
            segment,
            &calls[first..end],
        )?);
    }
    let children = children
        .try_into()
        .map_err(|_: Vec<ZkX509FixedAlgebraicScheduleV1>| {
            ZkX509ShaFixedAlgebraicErrorV1::Topology
        })?;
    Ok(children)
}
/// Compile all 472 verifier-owned SHA fixed columns for one admitted shape.
pub fn compile_zk_x509_sha_fixed_algebraic_schedule_v1(
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<ZkX509ShaFixedAlgebraicScheduleV1, ZkX509ShaFixedAlgebraicErrorV1> {
    let children = compile_sha_fixed_algebraic_children_v1(shape)?;
    ZkX509ShaFixedAlgebraicScheduleV1::new_v1(shape, children)
}
/// Return the success-only cached verifier-owned schedule for one admitted
/// disclosure shape.
///
/// Compilation failures are never cached, so a transient allocation failure
/// cannot poison the process-wide verifier schedule.
pub fn zk_x509_sha_fixed_algebraic_schedule_v1(
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<&'static ZkX509ShaFixedAlgebraicScheduleV1, ZkX509ShaFixedAlgebraicErrorV1> {
    let cache = ZK_X509_SHA_FIXED_ALGEBRAIC_SCHEDULES_V1
        .get(shape.disclosed_attributes)
        .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
    if let Some(schedule) = cache.get() {
        return Ok(schedule);
    }
    let schedule = compile_zk_x509_sha_fixed_algebraic_schedule_v1(shape)?;
    match cache.set(schedule) {
        Ok(()) => cache.get().ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology),
        Err(_racing_schedule) => cache.get().ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology),
    }
}
/// Compile the exact ordered per-shape schedule digest set for disclosures
/// `0, 1, 2, 3, 4`.
#[cfg(test)]
pub fn zk_x509_sha_fixed_algebraic_shape_digests_v1()
-> Result<[PrivacyOuterDigestV1; 5], ZkX509ShaFixedAlgebraicErrorV1> {
    let mut digests = [PrivacyOuterDigestV1::default(); 5];
    for (disclosed_attributes, digest) in digests.iter_mut().enumerate() {
        *digest = compile_zk_x509_sha_fixed_algebraic_schedule_v1(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes,
        })?
        .descriptor_digest_v1();
    }
    Ok(digests)
}
#[cfg(test)]
fn compile_sha_atom_accounting_v1(
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<ShaAtomAccountingV1, ZkX509ShaFixedAlgebraicErrorV1> {
    let children = compile_sha_fixed_algebraic_children_v1(shape)?;
    let mut atoms_by_column = vec![0_usize; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1];
    for (segment, child) in children.iter().enumerate() {
        let segment_start = segment
            .checked_mul(ZK_X509_SHA_BATCH_FIXED_WIDTH_V1)
            .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        for atom in child.atoms_v1() {
            let local_column = usize::from(match atom {
                ZkX509FixedAlgebraicAtomV1::Affine { column, .. }
                | ZkX509FixedAlgebraicAtomV1::Repeated { column, .. }
                | ZkX509FixedAlgebraicAtomV1::Sparse { column, .. } => *column,
            });
            let column = segment_start
                .checked_add(local_column)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
            let count = atoms_by_column
                .get_mut(column)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Topology)?;
            *count = count
                .checked_add(1)
                .ok_or(ZkX509ShaFixedAlgebraicErrorV1::Resource)?;
        }
    }
    let total_atoms = children.iter().map(|child| child.atoms_v1().len()).sum();
    if total_atoms != atoms_by_column.iter().copied().sum::<usize>() {
        return Err(ZkX509ShaFixedAlgebraicErrorV1::Topology);
    }
    Ok(ShaAtomAccountingV1 {
        total_atoms,
        atoms_by_column,
        child_digests: children.map(|child| child.descriptor_digest_v1()),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::sha_call_bus_stark::ZkX509ShaBatchFixedProviderV1;
    fn schedule(disclosed_attributes: usize) -> ZkX509ShaFixedAlgebraicScheduleV1 {
        compile_zk_x509_sha_fixed_algebraic_schedule_v1(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes,
        })
        .expect("closed SHA algebraic schedule")
    }
    fn unpinned_schedule(disclosed_attributes: usize) -> ZkX509ShaFixedAlgebraicScheduleV1 {
        let children = compile_sha_fixed_algebraic_children_v1(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes,
        })
        .expect("closed unpinned SHA algebraic children");
        ZkX509ShaFixedAlgebraicScheduleV1 {
            children,
            descriptor_digest: PrivacyOuterDigestV1::default(),
        }
    }
    #[test]
    fn exact_atom_accounting_matches_canonical_children_v1() {
        for disclosed_attributes in 0..=4 {
            let accounting = compile_sha_atom_accounting_v1(ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes,
            })
            .expect("count-only structural SHA compilation");
            let segment_atoms: Vec<usize> = accounting
                .atoms_by_column
                .chunks_exact(ZK_X509_SHA_BATCH_FIXED_WIDTH_V1)
                .map(|columns| columns.iter().sum())
                .collect();
            let local_column_atoms: Vec<(usize, usize)> = (0..ZK_X509_SHA_BATCH_FIXED_WIDTH_V1)
                .filter_map(|local| {
                    let atoms = (0..ZK_X509_SHA_SEGMENT_COUNT_V1)
                        .map(|segment| {
                            accounting.atoms_by_column
                                [segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 + local]
                        })
                        .sum();
                    (atoms != 0).then_some((local, atoms))
                })
                .collect();
            println!(
                "SHA_RAW_ACCOUNTING shape={disclosed_attributes} total={} segments={segment_atoms:?} \
                 child_digests={:?} local_columns={local_column_atoms:?}",
                accounting.total_atoms, accounting.child_digests,
            );
        }
    }
    fn expected_combined_row(
        provider: &ZkX509ShaBatchFixedProviderV1,
        row: usize,
    ) -> [F; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1] {
        let mut expected = [F::ZERO; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1];
        for segment in 0..ZK_X509_SHA_SEGMENT_COUNT_V1 {
            let fixed = provider
                .fixed_row_v1(segment, row)
                .expect("closed provider row");
            let start = segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
            expected[start..start + ZK_X509_SHA_BATCH_FIXED_WIDTH_V1].copy_from_slice(&fixed);
        }
        expected
    }
    fn reconstruct_native_chunk(
        schedule: &ZkX509ShaFixedAlgebraicScheduleV1,
        first_column: usize,
        width: usize,
    ) -> Vec<F> {
        let rows = ZK_X509_SHA_SEGMENT_ROWS_V1;
        let mut reconstructed = vec![F::ZERO; rows * width];
        for atom in schedule.atoms_v1().iter().copied() {
            let column = match atom {
                ZkX509FixedAlgebraicAtomV1::Affine { column, .. }
                | ZkX509FixedAlgebraicAtomV1::Repeated { column, .. }
                | ZkX509FixedAlgebraicAtomV1::Sparse { column, .. } => usize::from(column),
            };
            let Some(local_column) = column.checked_sub(first_column) else {
                continue;
            };
            if local_column >= width {
                continue;
            }
            let mut add = |row: u64, value: F| {
                let row = usize::try_from(row).expect("native row fits usize");
                let cell = reconstructed
                    .get_mut(row * width + local_column)
                    .expect("atom was schedule-bounded");
                *cell = cell.add(value);
            };
            match atom {
                ZkX509FixedAlgebraicAtomV1::Affine {
                    start,
                    end,
                    start_value,
                    step,
                    ..
                } => {
                    for row in start..end {
                        add(row, start_value.add(step.mul(F(row - start))));
                    }
                }
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                    ..
                } => {
                    for occurrence in 0..count {
                        add(
                            first + occurrence * stride,
                            start_value.add(step.mul(F(occurrence))),
                        );
                    }
                }
                ZkX509FixedAlgebraicAtomV1::Sparse { row, value, .. } => add(row, value),
            }
        }
        reconstructed
    }
    #[test]
    fn rfc_mapping_rejects_call_role_substitution_before_schedule_construction() {
        let shape = ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 4,
        };
        let calls = ZkX509ShaCallScheduleV1::new(shape).unwrap();
        let mut issuer = calls.calls()[12];
        assert!(rfc_consumer_v1(issuer, shape).unwrap().is_some());
        issuer.call = 3;
        assert_eq!(
            rfc_consumer_v1(issuer, shape),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        issuer.call = u8::MAX;
        assert_eq!(
            rfc_consumer_v1(issuer, shape),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
    }

    #[test]
    fn issuer_rfc_event_columns_match_native_schedule_at_every_call_row() {
        for disclosed_attributes in 0..=4 {
            let shape = ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes,
            };
            let provider = ZkX509ShaBatchFixedProviderV1::new_v1(shape).unwrap();
            let schedule = unpinned_schedule(disclosed_attributes);
            let issuer = provider.schedule().calls()[12];
            let segment = issuer.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1;
            let start = issuer.first_logical_row % ZK_X509_SHA_SEGMENT_ROWS_V1;
            for stream in 0..4 {
                let first = SHA_FIXED_RFC_STREAMS_V1 + stream * SHA_FIXED_RFC_STREAM_STRIDE_V1;
                let actual = reconstruct_native_chunk(
                    &schedule,
                    segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 + first,
                    SHA_FIXED_RFC_STREAM_STRIDE_V1,
                );
                for row in start..start + issuer.maximum_logical_rows() {
                    let expected = provider.fixed_row_v1(segment, row).unwrap();
                    assert_eq!(
                        &actual[row * SHA_FIXED_RFC_STREAM_STRIDE_V1
                            ..(row + 1) * SHA_FIXED_RFC_STREAM_STRIDE_V1],
                        &expected[first..first + SHA_FIXED_RFC_STREAM_STRIDE_V1],
                        "issuer RFC event mismatch: shape {disclosed_attributes}, stream {stream}, row {row}",
                    );
                }
            }
        }
    }

    #[test]
    fn structural_rows_match_closed_provider_at_all_boundaries() {
        for disclosed_attributes in 0..=4 {
            let shape = ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes,
            };
            let provider =
                ZkX509ShaBatchFixedProviderV1::new_v1(shape).expect("closed fixed provider");
            let schedule = unpinned_schedule(disclosed_attributes);
            let mut rows = BTreeSet::from([0, 1, ZK_X509_SHA_SEGMENT_ROWS_V1 - 1]);
            for (segment, active) in ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1
                .iter()
                .copied()
                .enumerate()
            {
                let _ = segment;
                rows.extend([active - 1, active]);
            }
            for manifest in provider.schedule().calls().iter().copied() {
                let segment_row = manifest.first_logical_row % ZK_X509_SHA_SEGMENT_ROWS_V1;
                rows.extend([
                    segment_row,
                    segment_row + 1,
                    segment_row + manifest.maximum_logical_rows() - 2,
                    segment_row + manifest.maximum_logical_rows() - 1,
                ]);
            }
            for row in rows {
                let mut actual = [F::ZERO; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1];
                schedule
                    .native_row_v1(u64::try_from(row).expect("row fits u64"), &mut actual)
                    .expect("algebraic native row");
                assert_eq!(
                    actual,
                    expected_combined_row(&provider, row),
                    "shape {disclosed_attributes}, row {row}"
                );
            }
        }
    }
    #[test]
    fn full_domain_native_equivalence_is_exact() {
        const CHUNK_COLUMNS: usize = 16;
        for disclosed_attributes in 0..=4 {
            let shape = ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes,
            };
            let provider =
                ZkX509ShaBatchFixedProviderV1::new_v1(shape).expect("closed fixed provider");
            let schedule = unpinned_schedule(disclosed_attributes);
            for first_column in (0..ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1).step_by(CHUNK_COLUMNS) {
                let width = CHUNK_COLUMNS.min(ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1 - first_column);
                let reconstructed = reconstruct_native_chunk(&schedule, first_column, width);
                let first_segment = first_column / ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
                let last_segment = (first_column + width - 1) / ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
                for row in 0..ZK_X509_SHA_SEGMENT_ROWS_V1 {
                    let first_expected = provider
                        .fixed_row_v1(first_segment, row)
                        .expect("closed full-domain provider row");
                    let last_expected = (last_segment != first_segment).then(|| {
                        provider
                            .fixed_row_v1(last_segment, row)
                            .expect("closed cross-segment provider row")
                    });
                    for local in 0..width {
                        let column = first_column + local;
                        let segment = column / ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
                        let segment_column = column % ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
                        let expected = if segment == first_segment {
                            first_expected[segment_column]
                        } else {
                            last_expected
                                .as_ref()
                                .expect("chunk spans the adjacent segment")[segment_column]
                        };
                        assert_eq!(
                            reconstructed[row * width + local],
                            expected,
                            "shape {disclosed_attributes}, native row {row}, combined column \
                             {column}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn all_formerly_reconstructed_columns_are_native_and_exact() {
        let shape = ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 0,
        };
        let provider = ZkX509ShaBatchFixedProviderV1::new_v1(shape).expect("closed fixed provider");
        let schedule = unpinned_schedule(0);
        for row in [
            0,
            1,
            ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[0] - 1,
            ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[0],
            ZK_X509_SHA_SEGMENT_ROWS_V1 - 1,
        ] {
            let mut actual = [F::ZERO; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1];
            schedule
                .native_row_v1(row as u64, &mut actual)
                .expect("algebraic native row");
            for segment in 0..ZK_X509_SHA_SEGMENT_COUNT_V1 {
                let expected = provider
                    .fixed_row_v1(segment, row)
                    .expect("closed fixed row");
                let start = segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
                assert_eq!(
                    &actual[start..start + SHA_WORD_CAPACITY_FIXED_WIDTH_V1],
                    &expected[..SHA_WORD_CAPACITY_FIXED_WIDTH_V1]
                );
            }
        }
    }
    #[test]
    fn descriptor_shape_set_and_invalid_shape_are_fail_closed() {
        let compiler_digest = zk_x509_sha_fixed_algebraic_compiler_descriptor_digest_v1()
            .expect("compiler descriptor digest");
        assert_ne!(compiler_digest, PrivacyOuterDigestV1::default());
        let first =
            zk_x509_sha_fixed_algebraic_shape_digests_v1().expect("five exact shape digests");
        let second = zk_x509_sha_fixed_algebraic_shape_digests_v1()
            .expect("deterministic five exact shape digests");
        assert_eq!(first, second);
        assert!(
            first
                .iter()
                .all(|digest| *digest != PrivacyOuterDigestV1::default())
        );
        assert!(first.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(matches!(
            compile_zk_x509_sha_fixed_algebraic_schedule_v1(ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes: 5,
            }),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        ));
    }
    #[test]
    fn success_only_shape_cache_is_stable_and_invalid_shapes_do_not_poison_it() {
        let shape = ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 0,
        };
        let first = zk_x509_sha_fixed_algebraic_schedule_v1(shape).expect("first cached schedule");
        let second =
            zk_x509_sha_fixed_algebraic_schedule_v1(shape).expect("second cached schedule");
        assert!(core::ptr::eq(first, second));
        assert_eq!(
            first,
            &compile_zk_x509_sha_fixed_algebraic_schedule_v1(shape)
                .expect("independently reproduced schedule")
        );
        assert!(matches!(
            zk_x509_sha_fixed_algebraic_schedule_v1(ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes: 5,
            }),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        ));
        assert!(core::ptr::eq(
            first,
            zk_x509_sha_fixed_algebraic_schedule_v1(shape).expect("valid cache remains available")
        ));
    }
    #[test]
    fn native_query_coset_and_output_shape_negatives_fail_closed() {
        for disclosed_attributes in 0..=4 {
            let schedule = unpinned_schedule(disclosed_attributes);
            let mut short = vec![F::ZERO; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1 - 1];
            assert!(schedule.native_row_v1(0, &mut short).is_err());
            let mut row = vec![F::ZERO; ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1];
            assert!(
                schedule
                    .native_row_v1(ZK_X509_SHA_SEGMENT_ROWS_V1 as u64, &mut row)
                    .is_err()
            );
            for query in [
                &[1_u64 << ZK_X509_MAIN_COMMON_LDE_LOG2_V1][..],
                &[][..],
                &[7, 7][..],
                &[8, 7][..],
            ] {
                assert!(schedule.evaluate_query_indices_v1(query).is_err());
            }
            for child in schedule.children_v1() {
                let mut child_short = vec![F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 - 1];
                assert!(child.native_row_v1(0, &mut child_short).is_err());
                let mut child_row = vec![F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1];
                assert!(
                    child
                        .native_row_v1(ZK_X509_SHA_SEGMENT_ROWS_V1 as u64, &mut child_row)
                        .is_err()
                );
                for query in [
                    &[1_u64 << ZK_X509_MAIN_COMMON_LDE_LOG2_V1][..],
                    &[][..],
                    &[7, 7][..],
                    &[8, 7][..],
                ] {
                    assert!(child.evaluate_query_indices_v1(query).is_err());
                }
            }
        }
    }
    #[test]
    fn nonzero_series_distinguishes_affine_repeated_and_irregular_three_points() {
        for (rows, values, kind) in [
            ([10, 11, 12], [3, 8, 13], 0),
            ([10, 20, 30], [3, 8, 13], 1),
            ([10, 11, 12], [3, 8, 8], 2),
            ([10, 20, 31], [3, 8, 13], 2),
        ] {
            let domain = ZkX509FixedAlgebraicDomainV1::new_v1(6, 7, F(GOLDILOCKS_GENERATOR_V1))
                .expect("test domain");
            let mut builder =
                ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 1).expect("test builder");
            let mut atom_count = 0;
            let mut series = NonzeroSeriesV1::empty_v1();
            for (row, value) in rows.into_iter().zip(values) {
                series
                    .observe_v1(
                        0,
                        NonzeroPointV1 {
                            row,
                            value: F(value),
                        },
                        &mut builder,
                        &mut atom_count,
                    )
                    .unwrap();
            }
            match (&series, kind) {
                (NonzeroSeriesV1::Affine { first, last, step }, 0) => {
                    assert_eq!((first.row, first.value), (10, F(3)));
                    assert_eq!((last.row, last.value, *step), (12, F(13), F(5)));
                    assert_eq!(atom_count, 0);
                }
                (
                    NonzeroSeriesV1::Repeated {
                        first,
                        last_row,
                        last_value,
                        count,
                        stride,
                        step,
                    },
                    1,
                ) => {
                    assert_eq!((first.row, first.value), (10, F(3)));
                    assert_eq!(
                        (*last_row, *last_value, *count, *stride, *step),
                        (30, F(13), 3, 10, F(5))
                    );
                    assert_eq!(atom_count, 0);
                }
                (NonzeroSeriesV1::Two(first, second), 2) => {
                    assert_eq!((first.row, first.value), (rows[1], F(values[1])));
                    assert_eq!((second.row, second.value), (rows[2], F(values[2])));
                    assert_eq!(atom_count, 1);
                }
                _ => panic!("three-point series chose the wrong representation: case {kind}"),
            }
        }
    }
    #[test]
    fn nonzero_series_rejects_non_increasing_construction_rows() {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(6, 7, F(GOLDILOCKS_GENERATOR_V1))
            .expect("test domain");
        let mut builder =
            ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 1).expect("test builder");
        let mut atom_count = 0;
        let mut series = NonzeroSeriesV1::empty_v1();
        for row in [10, 20, 30] {
            series
                .observe_v1(
                    0,
                    NonzeroPointV1 { row, value: F(row) },
                    &mut builder,
                    &mut atom_count,
                )
                .expect("increasing series");
        }
        assert_eq!(
            series.observe_v1(
                0,
                NonzeroPointV1 {
                    row: 29,
                    value: F(29),
                },
                &mut builder,
                &mut atom_count,
            ),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
    }
    #[test]
    fn interleaved_execution_replay_matches_committed_rows_not_grouped_helper_order() {
        let shape = ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 0,
        };
        let provider = ZkX509ShaBatchFixedProviderV1::new_v1(shape).expect("closed fixed provider");
        let manifest = provider
            .schedule()
            .call(4)
            .expect("maximum CRL-commitment call");
        let message = vec![0_u8; manifest.maximum_message_bytes];
        let circuit = build_sha256_word_circuit_v1(&message).expect("canonical shape circuit");
        let execution =
            interleaved_execution_memory_v1(&circuit).expect("authoritative local-event replay");
        assert_ne!(
            execution,
            circuit.stark_memory_v1().execution,
            "the circuit helper groups definitions before reads and is not the committed row order"
        );
        assert_eq!(execution.len(), manifest.maximum_memory_rows);
        let segment = manifest.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1;
        let call_start = manifest.first_logical_row % ZK_X509_SHA_SEGMENT_ROWS_V1;
        let memory_start = call_start + manifest.maximum_local_rows;
        for (memory_index, access) in execution.iter().copied().enumerate() {
            let fixed = provider
                .fixed_row_v1(segment, memory_start + memory_index)
                .expect("committed memory fixed row");
            assert_eq!(
                fixed[FIX_MEMORY_EXECUTION_ADDRESS], access.address,
                "execution address at memory row {memory_index}"
            );
            assert_eq!(
                fixed[FIX_MEMORY_EXECUTION_WRITE], access.is_write,
                "execution write selector at memory row {memory_index}"
            );
        }
    }
    #[test]
    fn sorted_memory_call_axis_is_block_and_occurrence_keyed() {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(6, 7, F(GOLDILOCKS_GENERATOR_V1))
            .expect("test domain");
        let mut builder = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        builder.begin_call_axis_group_v1().expect("call-axis group");
        for call in 0..3 {
            let call_start = call * 20;
            builder
                .observe_keyed_v1(
                    0,
                    FIX_MEMORY_NEW_NEXT,
                    call_start + 3,
                    CallAxisBlockV1::Sha(0),
                    9,
                    u32::MAX,
                    F::ONE,
                )
                .expect("first block boundary");
            builder
                .observe_keyed_v1(
                    0,
                    FIX_MEMORY_NEW_NEXT,
                    call_start + 7,
                    CallAxisBlockV1::Sha(1),
                    9,
                    u32::MAX,
                    F::ONE,
                )
                .expect("second block boundary");
            builder
                .observe_keyed_v1(
                    0,
                    FIX_MEMORY_SORTED_ADDRESS,
                    call_start + 11,
                    CallAxisBlockV1::Sha(0),
                    9,
                    0,
                    F(9),
                )
                .expect("first sorted occurrence");
            builder
                .observe_keyed_v1(
                    0,
                    FIX_MEMORY_SORTED_ADDRESS,
                    call_start + 13,
                    CallAxisBlockV1::Sha(0),
                    9,
                    1,
                    F(9),
                )
                .expect("second sorted occurrence");
        }
        builder
            .finish_call_axis_group_v1()
            .expect("closed call-axis group");
        let schedule = builder.finish_v1().expect("exact test schedule");
        assert_eq!(
            schedule.atoms_v1(),
            &[
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column: FIX_MEMORY_NEW_NEXT as u16,
                    first: 3,
                    count: 3,
                    stride: 20,
                    start_value: F::ONE,
                    step: F::ZERO,
                },
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column: FIX_MEMORY_NEW_NEXT as u16,
                    first: 7,
                    count: 3,
                    stride: 20,
                    start_value: F::ONE,
                    step: F::ZERO,
                },
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column: FIX_MEMORY_SORTED_ADDRESS as u16,
                    first: 11,
                    count: 3,
                    stride: 20,
                    start_value: F(9),
                    step: F::ZERO,
                },
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column: FIX_MEMORY_SORTED_ADDRESS as u16,
                    first: 13,
                    count: 3,
                    stride: 20,
                    start_value: F(9),
                    step: F::ZERO,
                },
            ]
        );
    }
    #[test]
    fn boolean_round_axis_is_exact_and_uses_32_atoms_per_block() {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            19,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release SHA domain");
        let mut builder = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        let compute_start = 101;
        let block_count = 2;
        emit_boolean_round_axis_atoms_v1(&mut builder, 0, compute_start, block_count)
            .expect("round-axis atoms");
        let schedule = builder.finish_v1().expect("closed round-axis schedule");
        assert_eq!(
            schedule.atoms_v1().len(),
            SHA_BOOLEAN_ROUND_AXIS_ATOMS_PER_BLOCK_V1 * block_count
        );
        for relative_row in 0..block_count * SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1 {
            let mut actual = [F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1];
            schedule
                .native_row_v1((compute_start + relative_row) as u64, &mut actual)
                .expect("round-axis native row");
            let within_block = relative_row % SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1;
            let boolean = within_block
                .checked_sub(SHA_ROUND_REGION_OFFSET_V1)
                .filter(|round_row| *round_row < SHA_ROUNDS_PER_BLOCK_V1 * SHA_ROUND_ROWS_V1)
                .and_then(|round_row| {
                    let within_round = round_row % SHA_ROUND_ROWS_V1;
                    [
                        (FIX_CHOOSE, SHA_CHOOSE_ROUND_OFFSET_V1),
                        (FIX_MAJORITY, SHA_MAJORITY_ROUND_OFFSET_V1),
                    ]
                    .into_iter()
                    .find_map(|(selector, operation_offset)| {
                        within_round
                            .checked_sub(operation_offset)
                            .filter(|chunk| *chunk < 4)
                            .map(|chunk| (selector, chunk))
                    })
                });
            for column in [
                FIX_CHOOSE,
                FIX_MAJORITY,
                FIX_BOOLEAN_FIRST,
                FIX_BOOLEAN_CONTINUE,
                FIX_BOOLEAN_LAST,
                FIX_BOOLEAN_SCALE,
                FIX_BOOLEAN_NEXT_SCALE,
            ] {
                let expected = boolean.map_or(F::ZERO, |(selector, chunk)| match column {
                    FIX_CHOOSE | FIX_MAJORITY => F(u64::from(column == selector)),
                    FIX_BOOLEAN_FIRST => F(u64::from(chunk == 0)),
                    FIX_BOOLEAN_CONTINUE => F(u64::from(chunk < 3)),
                    FIX_BOOLEAN_LAST => F(u64::from(chunk == 3)),
                    FIX_BOOLEAN_SCALE => F(1_u64 << (chunk * 8)),
                    FIX_BOOLEAN_NEXT_SCALE if chunk < 3 => F(1_u64 << ((chunk + 1) * 8)),
                    FIX_BOOLEAN_NEXT_SCALE => F::ZERO,
                    _ => unreachable!("covered boolean topology column"),
                });
                assert_eq!(
                    actual[column], expected,
                    "relative row {relative_row}, column {column}"
                );
            }
        }
    }
    #[test]
    fn boolean_block_gap_axis_is_exact_and_cancels_every_gap_row() {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            19,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release SHA domain");
        let mut builder = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        let compute_start = 101;
        let block_count = 14;
        emit_boolean_block_gap_axis_atoms_v1(&mut builder, 0, compute_start, block_count)
            .expect("block-gap atoms");
        let schedule = builder.finish_v1().expect("closed block-gap schedule");
        assert_eq!(
            schedule.atoms_v1().len(),
            SHA_BOOLEAN_BLOCK_GAP_ATOMS_PER_CALL_V1
        );
        for relative_row in 0..block_count * SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1 {
            let mut actual = [F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1];
            schedule
                .native_row_v1((compute_start + relative_row) as u64, &mut actual)
                .expect("block-gap native row");
            let within_block = relative_row % SHA_WORD_CAPACITY_LOCAL_ROWS_PER_BLOCK_V1;
            let boolean = within_block
                .checked_sub(SHA_ROUND_REGION_OFFSET_V1)
                .filter(|round_row| *round_row < SHA_ROUNDS_PER_BLOCK_V1 * SHA_ROUND_ROWS_V1)
                .and_then(|round_row| {
                    let within_round = round_row % SHA_ROUND_ROWS_V1;
                    [
                        (FIX_CHOOSE, SHA_CHOOSE_ROUND_OFFSET_V1),
                        (FIX_MAJORITY, SHA_MAJORITY_ROUND_OFFSET_V1),
                    ]
                    .into_iter()
                    .find_map(|(selector, operation_offset)| {
                        within_round
                            .checked_sub(operation_offset)
                            .filter(|chunk| *chunk < 4)
                            .map(|chunk| (selector, chunk))
                    })
                });
            for column in [
                FIX_CHOOSE,
                FIX_MAJORITY,
                FIX_BOOLEAN_FIRST,
                FIX_BOOLEAN_CONTINUE,
                FIX_BOOLEAN_LAST,
                FIX_BOOLEAN_SCALE,
                FIX_BOOLEAN_NEXT_SCALE,
            ] {
                let expected = boolean.map_or(F::ZERO, |(selector, chunk)| match column {
                    FIX_CHOOSE | FIX_MAJORITY => F(u64::from(column == selector)),
                    FIX_BOOLEAN_FIRST => F(u64::from(chunk == 0)),
                    FIX_BOOLEAN_CONTINUE => F(u64::from(chunk < 3)),
                    FIX_BOOLEAN_LAST => F(u64::from(chunk == 3)),
                    FIX_BOOLEAN_SCALE => F(1_u64 << (chunk * 8)),
                    FIX_BOOLEAN_NEXT_SCALE if chunk < 3 => F(1_u64 << ((chunk + 1) * 8)),
                    FIX_BOOLEAN_NEXT_SCALE => F::ZERO,
                    _ => unreachable!("covered boolean topology column"),
                });
                assert_eq!(
                    actual[column], expected,
                    "relative row {relative_row}, column {column}"
                );
            }
        }
        let mut negative = StructuralBuilderV1::new_v1(domain, 0).expect("negative builder");
        assert_eq!(
            emit_boolean_block_gap_axis_atoms_v1(&mut negative, 0, compute_start, 1),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            emit_boolean_block_gap_axis_atoms_v1(&mut negative, 0, compute_start, 13),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        let mut gap_row = [F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1];
        schedule
            .native_row_v1(
                (compute_start
                    + SHA_ROUND_REGION_OFFSET_V1
                    + SHA_CHOOSE_ROUND_OFFSET_V1
                    + SHA_ROUNDS_PER_BLOCK_V1 * SHA_ROUND_ROWS_V1) as u64,
                &mut gap_row,
            )
            .expect("first cancellation row");
        assert_eq!(gap_row[FIX_BOOLEAN_NEXT_SCALE], F::ZERO);
    }
    #[test]
    fn operation_read_phase_axis_is_exact_and_matches_its_atom_cost() {
        let block_count = 3;
        let message = vec![0_u8; 164];
        let circuit = build_sha256_word_circuit_v1(&message).expect("three-block word circuit");
        let execution =
            interleaved_execution_memory_v1(&circuit).expect("authoritative execution order");
        let digest_start = execution.len() - DIGEST_LOCAL_ROWS_PER_CALL_V1;
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            19,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release SHA domain");
        let memory_start = 1_234;
        let mut builder = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        emit_operation_read_axis_atoms_v1(&mut builder, 0, memory_start, block_count, &execution)
            .expect("operation-read phase-axis atoms");
        let schedule = builder.finish_v1().expect("closed phase-axis schedule");
        assert_eq!(
            schedule.atoms_v1().len(),
            operation_read_axis_atoms_per_call_v1(block_count).expect("exact atom cost")
        );
        for (memory_index, access) in execution[..digest_start].iter().copied().enumerate() {
            if access.is_write == F::ONE {
                continue;
            }
            let mut actual = [F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1];
            schedule
                .native_row_v1((memory_start + memory_index) as u64, &mut actual)
                .expect("phase-axis native row");
            assert_eq!(
                actual[FIX_MEMORY_EXECUTION_ADDRESS], access.address,
                "operation-read memory row {memory_index}"
            );
        }
        let mut malformed = execution.clone();
        let first_read = malformed[..digest_start]
            .iter()
            .position(|access| access.is_write == F::ZERO)
            .expect("at least one operation read");
        malformed[first_read].is_write = F::ONE;
        let mut negative = StructuralBuilderV1::new_v1(domain, 0).expect("negative builder");
        assert_eq!(
            emit_operation_read_axis_atoms_v1(
                &mut negative,
                0,
                memory_start,
                block_count,
                &malformed,
            ),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            emit_operation_read_axis_atoms_v1(&mut negative, 0, memory_start, block_count, &[],),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
    }
    #[test]
    fn sorted_memory_phase_axis_is_exact_and_rejects_malformed_topology() {
        let block_count = 3;
        let message = vec![0_u8; 164];
        let circuit = build_sha256_word_circuit_v1(&message).expect("three-block word circuit");
        let execution =
            interleaved_execution_memory_v1(&circuit).expect("authoritative execution order");
        let sorted = &circuit.stark_memory_v1().sorted;
        assert!(sorted[..7].iter().all(|access| access.address == F::ZERO));
        assert_eq!(sorted[7].address, F::ONE);
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            19,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release SHA domain");
        let memory_start = 4_321;
        let mut builder = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        emit_sorted_memory_phase_axis_atoms_v1(
            &mut builder,
            0,
            memory_start,
            block_count,
            &execution,
            sorted,
        )
        .expect("sorted-memory phase-axis atoms");
        let schedule = builder.finish_v1().expect("closed phase-axis schedule");
        assert_eq!(
            schedule.atoms_v1().len(),
            SHA_SORTED_PHASE_AXIS_ATOMS_PER_BLOCK_V1 * block_count
        );
        for (index, access) in sorted.iter().copied().enumerate() {
            let mut actual = [F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1];
            schedule
                .native_row_v1((memory_start + index) as u64, &mut actual)
                .expect("phase-axis native row");
            let same_next = sorted
                .get(index + 1)
                .is_some_and(|next| next.address == access.address);
            let new_next = index + 1 < sorted.len() && !same_next;
            assert_eq!(
                actual[FIX_MEMORY_SORTED_ADDRESS], access.address,
                "sorted address row {index}"
            );
            assert_eq!(
                actual[FIX_MEMORY_SORTED_WRITE], access.is_write,
                "sorted write row {index}"
            );
            assert_eq!(
                actual[FIX_MEMORY_SAME_NEXT],
                F(u64::from(same_next)),
                "SAME_NEXT row {index}"
            );
            assert_eq!(
                actual[FIX_MEMORY_NEW_NEXT],
                F(u64::from(new_next)),
                "NEW_NEXT row {index}"
            );
        }
        assert_eq!(
            schedule
                .native_row_v1(
                    (memory_start + sorted.len() - 1) as u64,
                    &mut [F::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1],
                )
                .map(|()| ()),
            Ok(())
        );
        let assert_rejected = |malformed: &[WordMemoryAccessV1]| {
            let mut negative = StructuralBuilderV1::new_v1(domain, 0).expect("negative builder");
            assert_eq!(
                emit_sorted_memory_phase_axis_atoms_v1(
                    &mut negative,
                    0,
                    memory_start,
                    block_count,
                    &execution,
                    malformed,
                ),
                Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
            );
        };
        let mut malformed_order = sorted.to_vec();
        malformed_order.swap(0, 7);
        assert_rejected(&malformed_order);
        let mut malformed_write = sorted.to_vec();
        malformed_write[0].is_write = F::ZERO;
        assert_rejected(&malformed_write);
        let mut malformed_address = sorted.to_vec();
        malformed_address
            .last_mut()
            .expect("last sorted row")
            .address = F(u64::try_from(
            INITIAL_LOCAL_ROWS_PER_CALL_V1 + block_count * SHA_WORDS_PER_BLOCK_V1,
        )
        .expect("word bound"));
        assert_rejected(&malformed_address);
        let mut malformed_occurrence = sorted.to_vec();
        let first_address_two = malformed_occurrence
            .iter()
            .position(|access| access.address == F(2))
            .expect("address two group");
        malformed_occurrence[first_address_two - 1].address = F(2);
        malformed_occurrence[first_address_two - 1].is_write = F::ONE;
        malformed_occurrence[first_address_two].is_write = F::ZERO;
        assert_rejected(&malformed_occurrence);
        assert_rejected(&sorted[..sorted.len() - 1]);
    }
    #[test]
    fn release_shape_atom_counts_and_digests_are_reported_and_bounded() {
        let compiler_digest = zk_x509_sha_fixed_algebraic_compiler_descriptor_digest_v1()
            .expect("compiler descriptor digest");
        eprintln!("zk-X509 SHA compiler descriptor digest: {compiler_digest:02x?}");
        for disclosed_attributes in 0..=4 {
            let schedule = schedule(disclosed_attributes);
            let child_atom_counts =
                core::array::from_fn::<_, ZK_X509_SHA_SEGMENT_COUNT_V1, _>(|segment| {
                    schedule.children_v1()[segment].atoms_v1().len()
                });
            let atom_count = schedule.atom_count_v1();
            eprintln!(
                "zk-X509 SHA shape {disclosed_attributes}: atoms={atom_count}, \
                 child_atoms={child_atom_counts:?}, child_digests={:02x?}, digest={:02x?}",
                core::array::from_fn::<_, ZK_X509_SHA_SEGMENT_COUNT_V1, _>(|segment| {
                    schedule.children_v1()[segment].descriptor_digest_v1()
                }),
                schedule.descriptor_digest_v1(),
            );
            assert!(
                child_atom_counts
                    .iter()
                    .all(|count| *count <= ZK_X509_SHA_FIXED_ALGEBRAIC_MAX_ATOMS_V1)
            );
        }
    }
    #[test]
    fn composite_children_are_pinned_and_reject_order_width_and_substitution_attacks() {
        for disclosed_attributes in 0..=4 {
            let schedule = schedule(disclosed_attributes);
            assert_eq!(
                core::array::from_fn(|segment| {
                    schedule.children_v1()[segment].atoms_v1().len()
                }),
                SHA_FIXED_ALGEBRAIC_CHILD_ATOM_COUNTS_V1,
            );
            assert!(
                schedule.children_v1().iter().all(|child| {
                    child.descriptor_digest_v1() != PrivacyOuterDigestV1::default()
                })
            );
        }
        let shape = ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 0,
        };
        let primary = schedule(0);
        let mut reordered = primary.children.clone();
        reordered.swap(0, 1);
        assert_eq!(
            ZkX509ShaFixedAlgebraicScheduleV1::new_v1(shape, reordered),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        let mut substituted = primary.children.clone();
        substituted[0] = substituted[1].clone();
        assert_eq!(
            ZkX509ShaFixedAlgebraicScheduleV1::new_v1(shape, substituted),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        let other_shape = schedule(1);
        let changed_child = primary
            .children
            .iter()
            .zip(&other_shape.children)
            .position(|(left, right)| left.descriptor_digest_v1() != right.descriptor_digest_v1())
            .expect("disclosure shape changes a child schedule");
        let mut cross_shape = primary.children.clone();
        cross_shape[changed_child] = other_shape.children[changed_child].clone();
        let cross_shape = ZkX509ShaFixedAlgebraicScheduleV1::new_v1(shape, cross_shape)
            .expect("the substituted child retains the same bounded geometry");
        assert_eq!(
            cross_shape.verify_descriptor_digest_v1(&primary.descriptor_digest_v1()),
            Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch)
        );
        let mut wrong_width = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
            primary.domain_v1(),
            u16::try_from(ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 - 1).expect("wrong width fits u16"),
        )
        .expect("bounded wrong-width child");
        wrong_width
            .push_sparse_v1(0, 0, F::ONE)
            .expect("canonical sparse child");
        let mut malformed_width = primary.children.clone();
        malformed_width[0] = wrong_width.finish_v1().expect("wrong-width schedule");
        assert_eq!(
            ZkX509ShaFixedAlgebraicScheduleV1::new_v1(shape, malformed_width),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            ZkX509ShaFixedAlgebraicScheduleV1::new_v1(
                ZkX509ShaCallPublicShapeV1 {
                    disclosed_attributes: 5,
                },
                primary.children.clone(),
            ),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        let mut changed_digest = primary.descriptor_digest_v1();
        let mut changed_words = changed_digest.to_bytes();
        changed_words[0] ^= 1;
        changed_digest = PrivacyOuterDigestV1::from_bytes(changed_words);
        assert_eq!(
            primary.verify_descriptor_digest_v1(&changed_digest),
            Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch)
        );
    }
    #[test]
    fn call_axis_lifecycle_topology_and_cap_fail_closed() {
        assert_eq!(
            transpose_run_to_call_axis_v1(0, 3),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            transpose_run_to_call_axis_v1(3, 0),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert!(!transpose_run_to_call_axis_v1(3, 3).expect("row axis wins a tie"));
        assert!(transpose_run_to_call_axis_v1(4, 3).expect("strictly smaller call axis"));
        assert_eq!(
            plan_boolean_topology_axis_v1(0, 3),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(3, 0),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(1, 12).expect("round axis is smaller"),
            BooleanTopologyAxisV1::Round
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(1, 13).expect("round axis wins the gap tie"),
            BooleanTopologyAxisV1::Round
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(1, 14).expect("block-gap axis is smaller"),
            BooleanTopologyAxisV1::BlockGap
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(1, 64).expect("block-gap beats the old-axis tie"),
            BooleanTopologyAxisV1::BlockGap
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(4, 3).expect("round axis beats the transposed call axis"),
            BooleanTopologyAxisV1::Round
        );
        assert_eq!(
            plan_boolean_topology_axis_v1(usize::MAX, 2),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Resource)
        );
        assert_eq!(
            operation_read_axis_atoms_per_call_v1(0),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            operation_read_axis_atoms_per_call_v1(1).expect("first block cost"),
            SHA_OPERATION_AXIS_FIRST_BLOCK_ATOMS_V1
        );
        assert_eq!(
            operation_read_axis_atoms_per_call_v1(3).expect("three-block cost"),
            130
        );
        assert_eq!(
            operation_read_axis_atoms_per_call_v1(usize::MAX),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Resource)
        );
        assert_eq!(
            transpose_operation_reads_to_phase_axis_v1(0, 3, false),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            transpose_operation_reads_to_phase_axis_v1(1, 3, true),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert!(
            transpose_operation_reads_to_phase_axis_v1(1, 33, false)
                .expect("phase axis is exactly smaller at 33 blocks")
        );
        assert!(
            !transpose_operation_reads_to_phase_axis_v1(1, 34, false)
                .expect("old block axis is smaller at 34 blocks")
        );
        assert!(
            transpose_operation_reads_to_phase_axis_v1(4, 3, true)
                .expect("phase axis beats the transposed call axis")
        );
        assert_eq!(
            transpose_sorted_memory_to_phase_axis_v1(0, 3, false),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            transpose_sorted_memory_to_phase_axis_v1(1, 3, true),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert!(
            transpose_sorted_memory_to_phase_axis_v1(1, 3, false)
                .expect("phase axis is strictly smaller for a short block-axis call")
        );
        assert!(
            transpose_sorted_memory_to_phase_axis_v1(16, 3, true)
                .expect("phase axis is strictly smaller")
        );
        assert!(
            !transpose_sorted_memory_to_phase_axis_v1(17, 3, true)
                .expect("old call axis is strictly smaller")
        );
        assert_eq!(
            transpose_sorted_memory_to_phase_axis_v1(usize::MAX, 1, true),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Resource)
        );
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(6, 7, F(GOLDILOCKS_GENERATOR_V1))
            .expect("test domain");
        let mut lifecycle = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        assert_eq!(
            lifecycle.finish_call_axis_group_v1(),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        lifecycle
            .begin_call_axis_group_v1()
            .expect("first call-axis group");
        assert_eq!(
            lifecycle.begin_call_axis_group_v1(),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            lifecycle.observe_keyed_v1(
                0,
                FIX_MEMORY_NEW_NEXT,
                ZK_X509_SHA_SEGMENT_ROWS_V1,
                CallAxisBlockV1::Sha(0),
                4,
                u32::MAX,
                F::ONE,
            ),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        lifecycle
            .observe_keyed_v1(
                0,
                FIX_MEMORY_NEW_NEXT,
                10,
                CallAxisBlockV1::Sha(0),
                4,
                u32::MAX,
                F::ONE,
            )
            .expect("first sorted key point");
        assert_eq!(
            lifecycle.observe_keyed_v1(
                0,
                FIX_MEMORY_NEW_NEXT,
                10,
                CallAxisBlockV1::Sha(0),
                4,
                u32::MAX,
                F::ONE,
            ),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        );
        let mut unclosed = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        unclosed
            .begin_call_axis_group_v1()
            .expect("unclosed call-axis group");
        assert!(matches!(
            unclosed.finish_v1(),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Topology)
        ));
        let mut capped = StructuralBuilderV1::new_v1(domain, 0).expect("structural builder");
        capped.atom_count = ZK_X509_SHA_FIXED_ALGEBRAIC_MAX_ATOMS_V1;
        capped
            .begin_call_axis_group_v1()
            .expect("bounded call-axis group");
        capped
            .observe_keyed_v1(
                0,
                FIX_MEMORY_NEW_NEXT,
                1,
                CallAxisBlockV1::Sha(0),
                0,
                u32::MAX,
                F::ONE,
            )
            .expect("deferred final atom");
        assert_eq!(
            capped.finish_call_axis_group_v1(),
            Err(ZkX509ShaFixedAlgebraicErrorV1::Resource)
        );
    }
}

#[cfg(test)]
mod extension_wrapper_tests {
    use super::*;
    use crate::privacy_engines::transparent_stark::{
        goldilocks_ifft_v1, goldilocks_primitive_root_v1,
    };

    #[test]
    fn extension_wrapper_preserves_all_child_columns_and_rejects_native_points() {
        // A small arithmetic fixture exercises the private forwarding owner;
        // the production constructor still accepts only its closed full schedule.
        let widths = [ZK_X509_SHA_BATCH_FIXED_WIDTH_V1; ZK_X509_SHA_SEGMENT_COUNT_V1];
        let domain =
            ZkX509FixedAlgebraicDomainV1::new_v1(3, 6, F(GOLDILOCKS_GENERATOR_V1)).unwrap();
        let children = core::array::from_fn(|child| {
            let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
                domain,
                u16::try_from(widths[child]).unwrap(),
            )
            .unwrap();
            builder
                .push_atom_v1(ZkX509FixedAlgebraicAtomV1::Sparse {
                    column: 0,
                    row: child as u64,
                    value: F(7 + child as u64),
                })
                .unwrap();
            builder
                .push_atom_v1(ZkX509FixedAlgebraicAtomV1::Sparse {
                    column: u16::try_from(widths[child] - 1).unwrap(),
                    row: 7,
                    value: F(19 + child as u64),
                })
                .unwrap();
            builder.finish_v1().unwrap()
        });
        let schedule = ZkX509ShaFixedAlgebraicScheduleV1 {
            children,
            descriptor_digest: PrivacyOuterDigestV1::default(),
        };
        let point = E::canonical([2, 3, 5, 7]).unwrap();
        let actual = schedule.evaluate_extension_point_v1(point).unwrap();
        assert_eq!(actual.len(), ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1);
        let root = goldilocks_primitive_root_v1(3).unwrap();
        let mut offset = 0;
        for (child, &width) in widths.iter().enumerate() {
            for column in 0..width {
                let mut coefficients = vec![F::ZERO; 8];
                if column == 0 {
                    coefficients[child] = F(7 + child as u64);
                }
                if column + 1 == width {
                    coefficients[7] = F(19 + child as u64);
                }
                goldilocks_ifft_v1(&mut coefficients, root).unwrap();
                let expected = coefficients.iter().rev().fold(E::ZERO, |sum, &value| {
                    sum.mul(point).add(E::from_base(value))
                });
                assert_eq!(actual[offset + column], expected);
            }
            offset += width;
        }
        assert_eq!(offset, actual.len());
        assert!(schedule.evaluate_extension_point_v1(E::ONE).is_err());
    }
}
