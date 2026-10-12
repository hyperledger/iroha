//! Frozen semantic profile of the shared backend transcript, as the q77 engine
//! instantiates it.
//!
//! The construction is the FIPS 202-based atomic whole-tape transcript,
//! version 1: SHA3-256 for every commitment, one atomic SHAKE256 tape per
//! verifier message, the complete canonical prefix in every hash input and
//! typed body frames. [`profile`] is the one typed descriptor of this
//! instantiation. Its complete canonical bytes are absorbed, in full, by every
//! commitment and challenge of the engine and are embedded in the artifact
//! descriptor; its SHA3-256 identity is what records and measurements name.
//!
//! Every number is read from the engine's own constants, so the descriptor
//! cannot describe another geometry than the one that runs. Rules that are
//! not numbers (sampling, ordering, addressing) are bound as versioned labels;
//! `specs/fastpq_deep_protocol_contract.md` defines each label.
//!
//! The descriptor holds semantic data only. It contains no source, build or
//! binary digest, no measurement, no qualification status and no caller
//! ceiling: admission policy is enforced separately and must not change proof
//! bytes. The declared envelope it binds is the profile's own fixed shape.
//!
//! Freezing this profile fixes what is bound and in what order. It does not
//! establish a soundness level.
//! TODO: B.2 supplies the round-by-round reduction for this exact geometry, the
//! mapping of the chained transcript to the BCS compilation and the checked
//! security accounting, including repeated attempts. The quantum random-oracle
//! claim and the complete hiding argument stay open until then. A query count
//! or FRI schedule that the accounting changes is a new descriptor and a new
//! identity; no old descriptor is kept.

use std::sync::OnceLock;

use fastpq_isi::{
    compact_challenge::{COMPOSITION_MASK_COEFFICIENTS, QUERY_RAW_WORDS},
    semantic_profile::{SemanticProfileKindV1, SemanticProfileV1, SemanticProfileValueV1 as Value},
};

use super::{
    compact_public_columns::{COMMITTED_COLUMN_COUNT, PUBLIC_COLUMN_COUNT},
    compact_sha3, deep_binding, deep_composition, deep_engine,
    deep_geometry::{
        CONSTRAINTS, COSET_OFFSET, FRI_ARITIES, FRI_DEGREES, FRI_LENGTHS, LDE_ROOT, LDE_ROWS,
        QUERY_CANDIDATES, QUERY_COUNT, TRACE_ROWS,
    },
    deep_masked_replay::{QUOTIENT_MASK_COEFFICIENTS, TRACE_MASK_COEFFICIENTS},
    deep_proof,
};
use crate::{
    field::{GOLDILOCKS_MODULUS_V1, GoldilocksFp4V1},
    gadgets::compact_smt_air::COLUMN_COUNT,
};

/// Name of the frozen transcript construction, carried by every prefix frame.
pub(super) const CONSTRUCTION: &str = "fips202-atomic-whole-tape-transcript-v1";
/// Stable name of this instantiation's profile.
pub(super) const NAME: &str = "fastpq.transcript.q77.v1";
/// Version of the descriptor's parameter list.
const DESCRIPTOR_VERSION: u64 = 1;
/// Version of the prefix and body framing; equals the prefix frame's `version`.
pub(super) const FRAMING_VERSION: u16 = 1;
/// Grinding difficulty of this profile. Zero means the proof frame has no
/// nonce and the profile claims no work-security term.
pub(super) const GRINDING_BITS: u64 = 0;

/// The typed descriptor of the frozen q77 transcript profile.
///
/// # Panics
/// Never for the fixed parameter list below; a label outside the profile
/// grammar would be a programming error caught by every test of this module.
pub(super) fn profile() -> &'static SemanticProfileV1 {
    static PROFILE: OnceLock<SemanticProfileV1> = OnceLock::new();
    PROFILE.get_or_init(build)
}

fn number(value: usize) -> Value<'static> {
    Value::U64(u64::try_from(value).expect("fixed profile dimension fits u64"))
}

fn list<const N: usize>(values: [usize; N]) -> [u64; N] {
    values.map(|value| u64::try_from(value).expect("fixed profile dimension fits u64"))
}

fn build() -> SemanticProfileV1 {
    use norito::schema::identity::NoritoSchema as _;

    let prefix_frame = compact_sha3::prefix_frame_name();
    let body_frame = compact_sha3::body_frame_name();
    let context_frame = deep_binding::context_frame_name();
    let proof_frame = deep_proof::DeepProof::frame_name();
    let arities = list(FRI_ARITIES);
    let lengths = list(FRI_LENGTHS);
    let degrees = list(FRI_DEGREES);
    let tapes: [u64; 10] = core::array::from_fn(|index| {
        let ordinal = u8::try_from(index + 1).expect("ten fixed rounds");
        u64::try_from(
            deep_binding::Round::new(ordinal)
                .expect("fixed transcript round")
                .tape_bytes(),
        )
        .expect("fixed tape extent fits u64")
    });
    SemanticProfileV1::new(
        SemanticProfileKindV1::Transcript,
        NAME,
        &[
            // Versions, construction and framing.
            ("descriptor_version", Value::U64(DESCRIPTOR_VERSION)),
            ("construction", Value::Text(CONSTRUCTION)),
            ("framing_version", Value::U64(u64::from(FRAMING_VERSION))),
            ("prefix_frame", Value::Text(&prefix_frame)),
            ("body_frame", Value::Text(&body_frame)),
            ("context_frame", Value::Text(&context_frame)),
            ("body_kinds", Value::Text("leaf=1,parent=2,chain=3,tape=4")),
            (
                "oracle_tags",
                Value::Text("row=1,quotient+mask=3,fri=4:round0-4,terminal=4:round5,ood=5"),
            ),
            // Primitives.
            ("commitment_hash", Value::Text("FIPS202:SHA3-256:suffix06")),
            ("commitment_bytes", number(deep_binding::COMMITMENT_BYTES)),
            ("challenge_xof", Value::Text("FIPS202:SHAKE256:suffix1f")),
            (
                "challenge_mode",
                Value::Text("atomic-whole-tape:one-tape-per-verifier-message:prefix+body"),
            ),
            // Field and encodings.
            ("field_modulus", Value::U64(GOLDILOCKS_MODULUS_V1)),
            ("base_encoding", Value::Text("canonical-u64-le")),
            ("extension_degree", Value::U64(4)),
            (
                "extension_nonresidue",
                Value::U64(deep_binding::EXTENSION_NONRESIDUE),
            ),
            (
                "extension_basis",
                Value::Text("polynomial-basis:1,u,u^2,u^3:u^4=nonresidue"),
            ),
            (
                "extension_encoding",
                Value::Text("four-canonical-u64-le-coefficients:constant-first"),
            ),
            ("extension_bytes", number(GoldilocksFp4V1::BYTES)),
            // Domains and relation geometry.
            ("trace_rows", number(TRACE_ROWS)),
            (
                "trace_root",
                Value::U64(fastpq_isi::FASTPQ_FINAL_V1.trace_root),
            ),
            ("evaluation_rows", number(LDE_ROWS)),
            ("evaluation_root", Value::U64(LDE_ROOT)),
            ("coset_offset", Value::U64(COSET_OFFSET)),
            ("columns", number(COLUMN_COUNT)),
            ("committed_columns", number(COMMITTED_COLUMN_COUNT)),
            ("public_columns", number(PUBLIC_COLUMN_COUNT)),
            ("constraints", number(CONSTRAINTS)),
            // Masking bounds and quotient split.
            ("trace_mask_coefficients", number(TRACE_MASK_COEFFICIENTS)),
            (
                "quotient_mask_coefficients",
                number(QUOTIENT_MASK_COEFFICIENTS),
            ),
            (
                "composition_mask_coefficients",
                number(COMPOSITION_MASK_COEFFICIENTS),
            ),
            (
                "quotient_split",
                Value::Text("q=q0+x^n*q1:masked-pair(q0+x^n*t,q1-t):joined-leaf(q0,q1,mask)"),
            ),
            // Out-of-domain claims and DEEP composition.
            ("ood_points", Value::Text("z,trace-root*z")),
            ("ood_answers", number(deep_binding::OOD_VALUES)),
            (
                "ood_answer_order",
                Value::Text("current-row,next-row,quotient-low,quotient-high"),
            ),
            ("deep_components", number(deep_composition::COMPONENTS)),
            (
                "deep_component_order",
                Value::Text("per-committed-column(h,x^2*h),then(t0,x*t0,t1,x*t1)"),
            ),
            (
                "deep_weights",
                Value::Text("composition-mask=1,component-k=lambda^k:k=1..components"),
            ),
            // FRI schedule, fibers and terminal.
            ("fri_arities", Value::U64List(&arities)),
            ("fri_lengths", Value::U64List(&lengths)),
            ("fri_degree_bounds", Value::U64List(&degrees)),
            (
                "fri_fiber_order",
                Value::Text("strided:fiber-j-holds-positions-j+k*(length/arity)"),
            ),
            (
                "fiber_encoding",
                Value::Text("arity-tag:omit-smallest-known-incoming-coordinate"),
            ),
            ("terminal_values", number(deep_proof::TERMINAL_VALUES)),
            ("terminal_degree_bound", number(FRI_DEGREES[5])),
            (
                "terminal_commitment",
                Value::Text("single-leaf-all-values:duplicated-child-parent"),
            ),
            (
                "merkle_addressing",
                Value::Text(
                    "binary:leaf(oracle,round,position):parent(oracle,round,level>=1,index):left-then-right",
                ),
            ),
            // Challenge sampling.
            ("queries", number(QUERY_COUNT)),
            ("query_candidates", number(QUERY_CANDIDATES)),
            ("query_raw_words", number(QUERY_RAW_WORDS)),
            (
                "word_sampler",
                Value::Text("u64-le-words:reject-ge-modulus:no-reduction:no-extra-squeeze"),
            ),
            (
                "ood_sampler",
                Value::Text("first-four-accepted-words:base-field-point-aborts"),
            ),
            (
                "query_sampler",
                Value::Text(
                    "all-candidates-first:reject-ge-largest-multiple-of-evaluation-rows:mod-evaluation-rows:first-distinct:ascending",
                ),
            ),
            // Message schedule and chain.
            ("tape_bytes", Value::U64List(&tapes)),
            (
                "schedule",
                Value::Text(
                    "1:dummy>row-root;2:alphas>quotient+mask-root;3:ood-point>ood-answers;4:lambda>fri-root-0;5:beta>fri-root-1;6:beta>fri-root-2;7:beta>fri-root-3;8:beta>fri-root-4;9:beta>terminal-root;10:queries",
                ),
            ),
            (
                "chain",
                Value::Text(
                    "zero-anchor:tape=g(prefix,tape-body(round,extent,predecessor)):next=h(prefix,chain-body(round,whole-tape,commitment))",
                ),
            ),
            (
                "abort_rule",
                Value::Text("wrong-phase,exhaustion,malformed-message,base-ood:permanent-abort"),
            ),
            // Grinding.
            ("grinding_bits", Value::U64(GRINDING_BITS)),
            ("grinding_nonce", Value::Text("none")),
            // Proof frame and the profile's declared envelope.
            ("proof_frame", Value::Text(&proof_frame)),
            (
                "max_relation_identity_bytes",
                number(deep_binding::MAX_RELATION_IDENTITY_BYTES),
            ),
            (
                "max_statement_bytes",
                number(deep_binding::MAX_STATEMENT_BYTES),
            ),
            (
                "max_context_bytes",
                number(compact_sha3::MAX_CONTEXT_BYTES),
            ),
            ("max_frame_bytes", number(deep_proof::MAX_FRAME_BYTES)),
            (
                "max_decode_allocation_charges",
                number(deep_proof::MAX_ALLOCATION_CHARGES),
            ),
            (
                "max_sequence_elements",
                number(deep_proof::MAX_SEQUENCE_ELEMENTS),
            ),
            ("max_total_elements", number(deep_proof::MAX_TOTAL_ELEMENTS)),
            ("max_decode_depth", number(deep_proof::MAX_DECODE_DEPTH)),
            ("max_fri_layers", number(FRI_LENGTHS.len())),
            ("max_merkle_path_levels", number(deep_engine::QUERY_PATH_LEN)),
            (
                "max_fiber_values",
                number(deep_engine::MAX_FRI_GROUP_VALUES),
            ),
            (
                "structural_work_accounting",
                Value::Text(
                    "v1:one-unit-per-enumerated-field-value-slot-and-numerator-evaluation-of-a-maximal-frame",
                ),
            ),
            (
                "structural_work_charge",
                number(deep_engine::VERIFICATION_WORK_UNITS),
            ),
        ],
    )
    .expect("fixed q77 transcript profile is a canonical semantic profile")
}

#[cfg(test)]
#[path = "transcript_profile/tests.rs"]
mod tests;
