/// Minimal native domain of both value-bus endpoints.
pub const P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1: usize = P256_VALUE_BUS_STARK_TRACE_SIZE_V1;
/// Native value-bus trace logarithm.
pub const P256_VALUE_BUS_AGGREGATE_TRACE_LOG2_V1: u8 = 19;
/// Minimal native arithmetic domain.
pub const P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1: usize = 1 << 19;
/// Native arithmetic trace logarithm.
pub const P256_ARITHMETIC_AGGREGATE_TRACE_LOG2_V1: u8 = 19;
/// Exact native vertical-window domain.
pub const P256_WINDOW_AGGREGATE_TRACE_SIZE_V1: usize = P256_CROSS_TRACE_WINDOW_TRACE_SIZE_V1;
/// Native vertical-window trace logarithm.
pub const P256_WINDOW_AGGREGATE_TRACE_LOG2_V1: u8 = 16;
/// Minimal protocol-supported native reduction domain.
pub const P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1: usize =
    P256_CROSS_TRACE_REDUCTION_TRACE_SIZE_V1;
/// Native reduction trace logarithm.
pub const P256_REDUCTION_AGGREGATE_TRACE_LOG2_V1: u8 = 5;
/// Minimal protocol-supported native wallet low-S domain.
pub const P256_LOW_S_AGGREGATE_TRACE_SIZE_V1: usize = P256_CROSS_TRACE_LOW_S_TRACE_SIZE_V1;
/// Native wallet low-S trace logarithm.
pub const P256_LOW_S_AGGREGATE_TRACE_LOG2_V1: u8 = 5;
/// Minimal padded external-binding sink domain.
pub const P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1: usize =
    P256_CROSS_TRACE_SINK_TRACE_SIZE_V1;
/// Native external-binding sink trace logarithm.
pub const P256_BINDING_SINK_AGGREGATE_TRACE_LOG2_V1: u8 = 16;
/// Exact packed scalar-bit bus domain.
pub const P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_SIZE_V1: usize =
    P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1;
/// Native packed scalar-bit bus trace logarithm.
pub const P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1: u8 = 8;
/// Strict upper bound on the factor count of every P-256 permutation
/// argument. The largest value-bus domain has `2^20` rows, with canonical
/// identity padding, so every active multiset has strictly fewer factors.
pub const P256_PERMUTATION_FACTOR_CARDINALITY_BOUND_V1: usize = 1 << 20;
/// Independent multiset arguments registered by one P-256 signature: value memory, external-cell
/// chain, arithmetic-cell copy, arithmetic scalar bits, and window scalar bits.
pub const P256_PERMUTATION_ARGUMENTS_PER_SIGNATURE_V1: usize = 5;
/// Certificate-or-CRL signatures in the canonical depth-three chain plus its signed CRL.
pub const P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1: usize = 4;
/// Wallet-ownership signatures in the canonical X5S1 statement.
pub const P256_X5S1_WALLET_SIGNATURES_V1: usize = 1;
/// Total P-256 signatures in one canonical X5S1 aggregate proof.
pub const P256_X5S1_SIGNATURES_V1: usize =
    P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 + P256_X5S1_WALLET_SIGNATURES_V1;
/// Exact number of four-lane P-256 multiset arguments in one X5S1 proof.
pub const P256_X5S1_PERMUTATION_ARGUMENTS_V1: usize =
    P256_X5S1_SIGNATURES_V1 * P256_PERMUTATION_ARGUMENTS_PER_SIGNATURE_V1;
/// Independent challenge lanes used by each P-256 permutation argument.
pub const P256_PERMUTATION_CHALLENGE_LANES_V1: usize = 4;
/// Conservative per-argument collision exponent. For Goldilocks,
/// `(2^20 - 1) / p < 2^-44`; four independent lanes therefore give a bound
/// strictly below `2^-176`.
pub const P256_PERMUTATION_LOCAL_COLLISION_BITS_V1: u16 = 176;
/// Conservative X5S1-wide exponent after the exact 25-argument union bound:
/// `25 * 2^-176 < 2^-171`.
pub const P256_X5S1_PERMUTATION_UNION_COLLISION_BITS_V1: u16 = 171;
/// Integrated value-execution auxiliary width.
pub const P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1: usize =
    P256_VALUE_BUS_STARK_AUX_WIDTH_V1
        + P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1
        + P256_VALUE_ARITHMETIC_COPY_AUX_WIDTH_V1;
/// Integrated value-execution fixed width.
pub const P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1: usize =
    P256_VALUE_BUS_STARK_FIXED_WIDTH_V1
        + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * 7
        + 3
        + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * 2
        + 3;
/// Integrated value-execution residue count.
pub const P256_VALUE_EXECUTION_AGGREGATE_CONSTRAINT_COUNT_V1: usize =
    P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1
        + P256_CROSS_TRACE_WRITER_CONSTRAINT_COUNT_V1
        + (P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1
            + P256_ARITHMETIC_COPY_LANES_V1 * (P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + 4));
/// Registered value-execution local constraint count; endpoint links are joined privately.
pub const P256_VALUE_EXECUTION_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_VALUE_EXECUTION_AGGREGATE_CONSTRAINT_COUNT_V1;
/// Registered sorted value-bus local constraint count; endpoint links are joined privately.
pub const P256_VALUE_SORTED_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1;
/// Scalar arithmetic source-product columns.
pub const P256_SCALAR_ARITHMETIC_SOURCE_AUX_WIDTH_V1: usize =
    8 + P256_SCALAR_BIT_BUS_LANES_V1 * 10;
/// Value-bus/arithmetic copy-product columns on the value-bus side.
pub const P256_VALUE_ARITHMETIC_COPY_AUX_WIDTH_V1: usize =
    P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1
        + P256_ARITHMETIC_COPY_LANES_V1 * (P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + 1)
        + P256_ARITHMETIC_COPY_LANES_V1;
/// Value-bus/arithmetic copy-product columns on the arithmetic side.
pub const P256_ARITHMETIC_VALUE_COPY_AUX_WIDTH_V1: usize =
    3 + P256_ARITHMETIC_COPY_LANES_V1 * 5;
/// Integrated arithmetic auxiliary width.
pub const P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1: usize = P256_ARITHMETIC_STARK_AUX_WIDTH_V1
    + P256_SCALAR_ARITHMETIC_SOURCE_AUX_WIDTH_V1
    + P256_ARITHMETIC_VALUE_COPY_AUX_WIDTH_V1;
/// Integrated arithmetic fixed width.
pub const P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1: usize =
    P256_ARITHMETIC_STARK_FIXED_WIDTH_V1 + 8 * 4 + 3 + 3 * 2 + 3;
/// Integrated arithmetic residue count.
pub const P256_ARITHMETIC_AGGREGATE_CONSTRAINT_COUNT_V1: usize =
    P256_ARITHMETIC_STARK_CONSTRAINT_COUNT_V1
        + (8 + P256_SCALAR_BIT_BUS_LANES_V1 * 12)
        + (3 + P256_ARITHMETIC_COPY_LANES_V1 * 7);
/// Registered arithmetic local constraint count; endpoint links are joined privately.
pub const P256_ARITHMETIC_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_ARITHMETIC_AGGREGATE_CONSTRAINT_COUNT_V1;
/// Scalar window source-product columns.
pub const P256_SCALAR_WINDOW_SOURCE_AUX_WIDTH_V1: usize =
    1 + P256_SCALAR_BIT_BUS_LANES_V1 * 3;
/// Integrated window auxiliary width.
pub const P256_WINDOW_AGGREGATE_AUX_WIDTH_V1: usize = P256_WINDOW_STARK_AUX_WIDTH_V1
    + P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1
    + P256_SCALAR_WINDOW_SOURCE_AUX_WIDTH_V1;
/// Integrated window fixed width.
pub const P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1: usize =
    P256_WINDOW_STARK_FIXED_WIDTH_V1 + 3 * 3 + 4 + 4 + 3;
/// Integrated window residue count.
pub const P256_WINDOW_AGGREGATE_CONSTRAINT_COUNT_V1: usize =
    P256_WINDOW_STARK_CONSTRAINT_COUNT_V1
        + (3 + P256_CROSS_TRACE_LANES_V1 * 7)
        + (1 + P256_SCALAR_BIT_BUS_LANES_V1 * 5);
/// Local source constraints; its four initial values are joined privately in MAIN.
pub const P256_WINDOW_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1: usize =
    P256_WINDOW_AGGREGATE_CONSTRAINT_COUNT_V1 - P256_CROSS_TRACE_LANES_V1;
/// Registered window local constraint count; endpoint links are joined privately.
pub const P256_WINDOW_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_WINDOW_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1;
/// Integrated reduction auxiliary width.
pub const P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1: usize =
    P256_REDUCTION_STARK_AUX_WIDTH_V1 + P256_CROSS_TRACE_REDUCTION_AUX_WIDTH_V1;
/// Integrated reduction fixed width.
pub const P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1: usize =
    P256_REDUCTION_STARK_FIXED_WIDTH_V1 + 2 * 3 + 3;
/// Integrated reduction residue count.
pub const P256_REDUCTION_AGGREGATE_CONSTRAINT_COUNT_V1: usize =
    P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1 + (2 + P256_CROSS_TRACE_LANES_V1 * 6);
/// Local source constraints; its four initial values are joined privately in MAIN.
pub const P256_REDUCTION_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1: usize =
    P256_REDUCTION_AGGREGATE_CONSTRAINT_COUNT_V1 - P256_CROSS_TRACE_LANES_V1;
/// Registered reduction local constraint count; endpoint links are joined privately.
pub const P256_REDUCTION_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_REDUCTION_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1;
/// Integrated wallet low-S auxiliary width.
pub const P256_LOW_S_AGGREGATE_AUX_WIDTH_V1: usize =
    P256_LOW_S_STARK_AUX_WIDTH_V1 + P256_CROSS_TRACE_LOW_S_AUX_WIDTH_V1;
/// Integrated wallet low-S fixed width.
pub const P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1: usize =
    P256_LOW_S_STARK_FIXED_WIDTH_V1 + 3 + 3;
/// Integrated wallet low-S residue count.
pub const P256_LOW_S_AGGREGATE_CONSTRAINT_COUNT_V1: usize =
    P256_LOW_S_STARK_CONSTRAINT_COUNT_V1 + (1 + P256_CROSS_TRACE_LANES_V1 * 5);
/// Local source constraints; its four initial values are joined privately in MAIN.
pub const P256_LOW_S_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1: usize =
    P256_LOW_S_AGGREGATE_CONSTRAINT_COUNT_V1 - P256_CROSS_TRACE_LANES_V1;
/// Registered low-S local constraint count; endpoint links are joined privately.
pub const P256_LOW_S_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_LOW_S_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1;
/// Bytes in one complete `(Qx,Qy,r,s,digest)` P-256 input tuple.
#[cfg(test)]
pub use super::p256_external_binding_air::P256_INPUT_SELECTION_BYTES_V1;
/// External-binding committed base width, including both selected byte words,
/// their range decompositions, and the private depth selector.
pub const P256_BINDING_SINK_BASE_WIDTH_V1: usize =
    2 * P256_EXTERNAL_BINDINGS_PER_ROW_V1 + 3 + 2 * 8;
/// External-binding verifier preprocessing width.
pub const P256_BINDING_SINK_FIXED_WIDTH_V1: usize =
    3 * P256_EXTERNAL_BINDINGS_PER_ROW_V1 + 3 * 6 + 3 + 6;
/// External-binding residue count.
pub const P256_BINDING_SINK_CONSTRAINT_COUNT_V1: usize =
    P256_CROSS_TRACE_SINK_CONSTRAINT_COUNT_V1 + 41;
/// Maximum sink degree including verifier-fixed gates and optional-input selection.
pub const P256_BINDING_SINK_CONSTRAINT_DEGREE_V1: u8 = 3;
/// Registered sink local constraint count; endpoint links are joined privately.
pub const P256_BINDING_SINK_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_BINDING_SINK_CONSTRAINT_COUNT_V1;
/// Registered scalar-bit bus local constraint count; endpoint links are joined privately.
pub const P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1: usize =
    P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1;
const CROSS_EVENT_FIXED_WIDTH: usize = 3;
const CROSS_BOUNDARY_FIXED_WIDTH: usize = 3;
const SCALAR_EVENT_FIXED_WIDTH: usize = 4;
const ARITHMETIC_COPY_EVENT_FIXED_WIDTH: usize = 2;
const VALUE_WRITER_FIXED_WIDTH: usize = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1
    * (CROSS_EVENT_FIXED_WIDTH + 4)
    + CROSS_BOUNDARY_FIXED_WIDTH;
const VALUE_WRITER_EVENT: usize = 0;
const VALUE_WRITER_MULTIPLICITIES: usize =
    VALUE_WRITER_EVENT + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * CROSS_EVENT_FIXED_WIDTH;
const VALUE_WRITER_BOUNDARY: usize =
    VALUE_WRITER_MULTIPLICITIES + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * 4;
const VALUE_NATIVE_AUX: usize = 0;
const VALUE_WRITER_AUX: usize = VALUE_NATIVE_AUX + P256_VALUE_BUS_STARK_AUX_WIDTH_V1;
const VALUE_ARITHMETIC_COPY_AUX: usize = VALUE_WRITER_AUX + P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1;
const VALUE_NATIVE_FIXED: usize = 0;
const VALUE_WRITER_FIXED: usize = VALUE_NATIVE_FIXED + P256_VALUE_BUS_STARK_FIXED_WIDTH_V1;
const VALUE_ARITHMETIC_COPY_FIXED: usize = VALUE_WRITER_FIXED + VALUE_WRITER_FIXED_WIDTH;
const VALUE_ARITHMETIC_COPY_BOUNDARY_FIXED: usize = VALUE_ARITHMETIC_COPY_FIXED
    + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
const WINDOW_NATIVE_AUX: usize = 0;
const WINDOW_CROSS_AUX: usize = WINDOW_NATIVE_AUX + P256_WINDOW_STARK_AUX_WIDTH_V1;
const WINDOW_SCALAR_AUX: usize = WINDOW_CROSS_AUX + P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1;
const WINDOW_NATIVE_FIXED: usize = 0;
const WINDOW_CROSS_FIXED: usize = WINDOW_NATIVE_FIXED + P256_WINDOW_STARK_FIXED_WIDTH_V1;
const WINDOW_SCALAR_FIXED: usize = WINDOW_CROSS_FIXED + 3 * CROSS_EVENT_FIXED_WIDTH;
const WINDOW_SCALAR_BIT_SELECTORS_FIXED: usize = WINDOW_SCALAR_FIXED + SCALAR_EVENT_FIXED_WIDTH;
const WINDOW_BOUNDARY_FIXED: usize = WINDOW_SCALAR_BIT_SELECTORS_FIXED + 4;
const REDUCTION_NATIVE_AUX: usize = 0;
const REDUCTION_CROSS_AUX: usize = REDUCTION_NATIVE_AUX + P256_REDUCTION_STARK_AUX_WIDTH_V1;
const REDUCTION_NATIVE_FIXED: usize = 0;
const REDUCTION_CROSS_FIXED: usize = REDUCTION_NATIVE_FIXED + P256_REDUCTION_STARK_FIXED_WIDTH_V1;
const REDUCTION_BOUNDARY_FIXED: usize = REDUCTION_CROSS_FIXED + 2 * CROSS_EVENT_FIXED_WIDTH;
const LOW_S_NATIVE_AUX: usize = 0;
const LOW_S_CROSS_AUX: usize = LOW_S_NATIVE_AUX + P256_LOW_S_STARK_AUX_WIDTH_V1;
const LOW_S_NATIVE_FIXED: usize = 0;
const LOW_S_CROSS_FIXED: usize = LOW_S_NATIVE_FIXED + P256_LOW_S_STARK_FIXED_WIDTH_V1;
const LOW_S_BOUNDARY_FIXED: usize = LOW_S_CROSS_FIXED + CROSS_EVENT_FIXED_WIDTH;
const ARITHMETIC_NATIVE_AUX: usize = 0;
const ARITHMETIC_SCALAR_AUX: usize = ARITHMETIC_NATIVE_AUX + P256_ARITHMETIC_STARK_AUX_WIDTH_V1;
const ARITHMETIC_NATIVE_FIXED: usize = 0;
const ARITHMETIC_SCALAR_FIXED: usize =
    ARITHMETIC_NATIVE_FIXED + P256_ARITHMETIC_STARK_FIXED_WIDTH_V1;
const ARITHMETIC_BOUNDARY_FIXED: usize = ARITHMETIC_SCALAR_FIXED + 8 * SCALAR_EVENT_FIXED_WIDTH;
const ARITHMETIC_VALUE_COPY_AUX: usize =
    ARITHMETIC_SCALAR_AUX + P256_SCALAR_ARITHMETIC_SOURCE_AUX_WIDTH_V1;
const ARITHMETIC_VALUE_COPY_FIXED: usize = ARITHMETIC_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH;
const ARITHMETIC_VALUE_COPY_BOUNDARY_FIXED: usize =
    ARITHMETIC_VALUE_COPY_FIXED + 3 * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
const WINDOW_CANDIDATE_EVENTS: usize = 2 * 64 * 16 * 3 * 16;
const WINDOW_OUTPUT_EVENTS: usize = 2 * 64 * 3 * 16;
const WINDOW_EXTERNAL_EVENTS: usize = WINDOW_CANDIDATE_EVENTS + WINDOW_OUTPUT_EVENTS;
const DIGEST_REDUCTION_OUTPUT_ADDRESS: usize = WINDOW_EXTERNAL_EVENTS;
const RESULT_X_REDUCTION_OUTPUT_ADDRESS: usize =
    DIGEST_REDUCTION_OUTPUT_ADDRESS + P256_REDUCTION_ROWS_V1;
const RESULT_X_REDUCTION_SOURCE_ADDRESS: usize =
    RESULT_X_REDUCTION_OUTPUT_ADDRESS + P256_REDUCTION_ROWS_V1;
const LOW_S_ADDRESS: usize = RESULT_X_REDUCTION_SOURCE_ADDRESS + P256_REDUCTION_ROWS_V1;
const P256_ARITHMETIC_OPERATIONS_V1: usize = 14_828;
#[cfg(test)]
const P256_ARITHMETIC_COPY_CELLS_V1: usize = P256_ARITHMETIC_OPERATIONS_V1 * 16 * 3;
const _: () =
    assert!(P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_VALUE_BUS_AGGREGATE_TRACE_LOG2_V1);
const _: () = assert!(
    P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_ARITHMETIC_AGGREGATE_TRACE_LOG2_V1
);
const _: () =
    assert!(P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_WINDOW_AGGREGATE_TRACE_LOG2_V1);
const _: () =
    assert!(P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_REDUCTION_AGGREGATE_TRACE_LOG2_V1);
const _: () =
    assert!(P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_LOW_S_AGGREGATE_TRACE_LOG2_V1);
const _: () = assert!(
    P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_BINDING_SINK_AGGREGATE_TRACE_LOG2_V1
);
const _: () = assert!(
    P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_SIZE_V1 == 1 << P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1
);
const _: () = assert!(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 == 2);
const _: () =
    assert!(P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 == P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1);
const _: () = assert!(P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1 == 116);
const _: () = assert!(P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1 == 46);
const _: () = assert!(P256_VALUE_EXECUTION_AGGREGATE_CONSTRAINT_COUNT_V1 == 210);
const _: () = assert!(P256_VALUE_EXECUTION_REGISTERED_CONSTRAINT_COUNT_V1 == 210);
const _: () = assert!(P256_VALUE_SORTED_REGISTERED_CONSTRAINT_COUNT_V1 == 90);
const _: () = assert!(P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1 == 72);
const _: () = assert!(P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1 == 134);
const _: () = assert!(P256_WINDOW_AGGREGATE_AUX_WIDTH_V1 == 37);
const _: () = assert!(P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1 == 47);
const _: () = assert!(P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1 == 19);
const _: () = assert!(P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1 == 45);
const _: () = assert!(P256_LOW_S_AGGREGATE_AUX_WIDTH_V1 == 14);
const _: () = assert!(P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1 == 42);
const _: () = assert!(P256_BINDING_SINK_BASE_WIDTH_V1 == 25);
const _: () = assert!(P256_BINDING_SINK_FIXED_WIDTH_V1 == 36);
const _: () = assert!(P256_CROSS_TRACE_CHALLENGE_TERMS_V1 == 4);
const _: () = assert!(P256_CROSS_TRACE_LANES_V1 == P256_VALUE_BUS_LANES_V1);
const _: () = assert!(P256_CROSS_TRACE_LANES_V1 == P256_SCALAR_BIT_BUS_LANES_V1);
const _: () = assert!(P256_CROSS_TRACE_LANES_V1 == P256_ARITHMETIC_COPY_LANES_V1);
const _: () = assert!(P256_X5S1_SIGNATURES_V1 == 5);
const _: () = assert!(P256_X5S1_PERMUTATION_ARGUMENTS_V1 == 25);
const _: () = assert!(P256_PERMUTATION_LOCAL_COLLISION_BITS_V1 == 176);
const _: () = assert!(P256_X5S1_PERMUTATION_UNION_COLLISION_BITS_V1 == 171);
