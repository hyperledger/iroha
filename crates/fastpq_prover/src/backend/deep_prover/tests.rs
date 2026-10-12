//! Whole-attempt budget/entropy controls and an explicit full-size native diagnostic.

use super::*;
use crate::{
    backend::{air::WorkLimits, compact_transfer_air::CompactTransferAir},
    gadgets::compact_smt_air::{PublicStatement, PublicUpdate},
};
use rand::{SeedableRng, TryRngCore, rngs::StdRng};

#[path = "diagnostic_artifact.rs"]
mod diagnostic_artifact;

const COMPLETE_CONTEXT: &[u8] = b"native producer diagnostic";
// Seeded complete proof under the frozen transcript profile: a golden of the
// current source, regenerated with
// `generate_current_seeded_proof_for_review_with_all_relation_controls` and
// replaced deliberately when the profile or the wire changes. It pins bytes and
// approves nothing. Verification, negative controls and required-Metal parity
// still check these bytes.
const COMPLETE_BYTES: usize = 484_374;
const COMPLETE_HASH: &str = "eb3de327c1632512113999d1174887bca63763a1715e353948ffcee71dcd2c01";

/// The fixed profile's exact relation shape with the given attempt ceilings
/// and no additional statement ceiling.
fn work(max_payload_bytes: usize, max_work_units: usize) -> WorkLimits {
    WorkLimits {
        max_statement_bytes: usize::MAX,
        max_payload_bytes,
        max_work_units,
        ..VerifierLimits::exact(0).work
    }
}
fn limits() -> ProducerLimits {
    ProducerLimits {
        digest_execution: DigestExecutionV1::Cpu,
        work: work(usize::MAX, usize::MAX),
        max_hash_calls: usize::MAX,
        max_proof_bytes: deep_proof::PROOF_BYTE_TARGET,
    }
}
fn digest(seed: u8) -> [u32; 8] {
    limbs(iroha_crypto::Hash::new([seed; 33]).as_ref())
}
fn limbs(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}
fn statement() -> PublicStatement {
    PublicStatement {
        updates: [
            PublicUpdate {
                old_leaf: digest(1),
                new_leaf: digest(2),
                path: 7,
            },
            PublicUpdate {
                old_leaf: digest(3),
                new_leaf: digest(4),
                path: 11,
            },
        ],
        old_root: digest(5),
        new_root: digest(6),
    }
}
struct NoEntropy(usize);
impl TryRngCore for NoEntropy {
    type Error = &'static str;
    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        self.0 += 1;
        Err("unexpected entropy")
    }
    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        self.0 += 1;
        Err("unexpected entropy")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> std::result::Result<(), Self::Error> {
        self.0 += 1;
        Err("unexpected entropy")
    }
}
impl TryCryptoRng for NoEntropy {}

#[test]
#[cfg(feature = "fastpq-gpu")]
fn required_device_failure_precedes_source_reading_and_entropy() {
    let air = CompactTransferAir::new(&statement(), None).unwrap();
    let plan = ProducerPlan::new(
        &air,
        ProducerLimits {
            digest_execution: DigestExecutionV1::Device(crate::Digest384GpuBackendV1::Cuda),
            ..limits()
        },
    )
    .unwrap();
    let mut rng = NoEntropy(0);
    assert!(matches!(
        plan.build_from_borrowed_for_test(&[], &mut rng),
        Err(Error::NativeDigestExecution { .. })
    ));
    assert_eq!(rng.0, 0);
}

#[test]
fn whole_attempt_preflight_binds_every_budget_before_entropy_or_private_allocation() {
    use crate::backend::compact_protocol::FixedAir as _;
    type Lower = fn(&mut WorkLimits);
    let air = CompactTransferAir::new(&statement(), None).unwrap();
    let plan = ProducerPlan::new(&air, limits()).unwrap();
    eprintln!(
        "deep_complete_producer_payload_bytes={}; structural_work_units={}; hash_calls={}",
        plan.payload_bytes, plan.work_units, plan.hash_calls
    );
    assert!(plan.payload_bytes < 2 * 1024 * 1024 * 1024);
    assert!(plan.payload_bytes > plan.quotient.payload_bytes);
    assert!(plan.work_units > plan.quotient.work_units);
    assert!(plan.hash_calls > 2 * (2 * LDE_ROWS - 1));
    assert!(plan.hash_calls < 3 * (2 * LDE_ROWS - 1));
    assert!(plan.payload_bytes > plan.replay.payload_bytes);
    let exact = ProducerLimits {
        digest_execution: DigestExecutionV1::Cpu,
        work: WorkLimits {
            max_statement_bytes: air.statement_bytes().len(),
            ..work(plan.payload_bytes, plan.work_units)
        },
        max_hash_calls: plan.hash_calls,
        max_proof_bytes: deep_proof::MAX_FRAME_BYTES,
    };
    assert!(ProducerPlan::new(&air, exact).is_ok());
    for budget in [
        ProducerLimits {
            work: work(plan.payload_bytes - 1, plan.work_units),
            ..exact
        },
        ProducerLimits {
            work: work(plan.payload_bytes, plan.work_units - 1),
            ..exact
        },
        ProducerLimits {
            max_hash_calls: exact.max_hash_calls - 1,
            ..exact
        },
        ProducerLimits {
            max_proof_bytes: exact.max_proof_bytes - 1,
            ..exact
        },
    ] {
        assert!(ProducerPlan::new(&air, budget).is_err());
    }
    // Every relation ceiling of the typed interface limits is exact as well:
    // one below the sealed relation's declared shape or statement is refused
    // by name before any plan is derived.
    let relation_ceilings: [(&str, usize, Lower); 4] = [
        ("max_deep_producer_trace_rows", TRACE_ROWS, |w| {
            w.max_trace_rows -= 1;
        }),
        ("max_deep_producer_trace_cells", TRACE_ROWS * 342, |w| {
            w.max_trace_cells -= 1
        }),
        ("max_deep_producer_constraints", CONSTRAINTS, |w| {
            w.max_constraints -= 1;
        }),
        (
            "max_deep_producer_statement_bytes",
            air.statement_bytes().len(),
            |w| w.max_statement_bytes -= 1,
        ),
    ];
    for (name, required, lower) in relation_ceilings {
        let mut limited = exact;
        lower(&mut limited.work);
        assert!(matches!(
            ProducerPlan::new(&air, limited),
            Err(Error::VerifierLimitExceeded { limit, actual, max })
                if limit == name && actual == required && max == required - 1
        ));
    }
    let mut rng = NoEntropy(0);
    // A valid plan cannot turn an absent source into entropy consumption or a tree.
    assert!(plan.build_from_borrowed_for_test(&[], &mut rng).is_err());
    assert_eq!(rng.0, 0);
    assert!(
        ProducerPlan::new(
            &air,
            ProducerLimits {
                work: work(0, usize::MAX),
                ..limits()
            }
        )
        .is_err()
    );
}

#[test]
fn self_check_work_keeps_the_producer_and_rejects_invalid_decomposition() {
    assert_eq!(quotient_and_self_check_work(1000, 700).unwrap(), 1300);
    assert_eq!(quotient_and_self_check_work(0, 0).unwrap(), 0);
    assert_eq!(
        quotient_and_self_check_work(usize::MAX, usize::MAX).unwrap(),
        usize::MAX
    );
    assert!(quotient_and_self_check_work(0, 1).is_err());
    assert!(quotient_and_self_check_work(usize::MAX, 0).is_err());
}

#[test]
fn public_self_check_allowance_dominates_the_complete_bounded_verifier() {
    use super::super::{
        compact_hash_quotient::{
            MAX_PROVER_LEDGER_NODES, MAX_PROVER_OUTPUT_TERMS, MAX_PROVER_SELECTOR_MASKS,
            MAX_PROVER_SELECTOR_RUNS,
        },
        compact_smt_quotient::{FIXED_COLUMN_COUNT, FIXED_ROW_COUNT, RESIDUE_COUNT},
        deep_geometry::{FRI_ARITIES, FRI_LENGTHS},
    };
    use crate::gadgets::compact_smt_air::{COLUMN_COUNT, PHYSICAL_HASH_ROWS};

    // Independent, deliberately loose source-loop bound for verify_decoded:
    // geometry validation, four periodic selector evaluations, sparse public
    // setup/evaluation, one compiled hash/SMT AIR evaluation, q DEEP rows, all
    // five FRI fibers and their q-by-q matching, and the complete terminal DFT.
    // A unit below gets 16384 scalar field/index operations. A quartic inverse
    // uses fewer than 12000 such operations after expanding every Fp4 product
    // (19 base multiplies and 19 adds). A direct SMT slot has at most 256
    // Fp4 operations, also below this margin. Nested variable extents are explicit.
    // Include every bounded frame byte for decode/preflight/canonical checks.
    // SHA3 permutations and transcript bytes retain their separate exact ledger.
    let public_units = 128
        + 4 * PHYSICAL_HASH_ROWS
        + 2 * FIXED_ROW_COUNT * (FIXED_COLUMN_COUNT + 2)
        + MAX_PROVER_LEDGER_NODES
        + 2 * MAX_PROVER_OUTPUT_TERMS
        + 2 * MAX_PROVER_SELECTOR_RUNS
        + MAX_PROVER_SELECTOR_MASKS
        + RESIDUE_COUNT
        + 4 * COLUMN_COUNT
        + 2 * CONSTRAINTS;
    let query_units = QUERY_COUNT
        * (2 * COMMITTED_COLUMN_COUNT
            + 128
            + FRI_ARITIES
                .iter()
                .map(|&arity| arity * arity + QUERY_COUNT + 128)
                .sum::<usize>());
    let terminal = FRI_LENGTHS[5];
    let verifier_work_bound =
        16384 * (public_units + query_units + terminal.pow(2) + deep_proof::MAX_FRAME_BYTES);
    // This is only the direct SMT portion of the retained 4N numerator point
    // allowance; public preparation, hash AIR, FFT and division are additional.
    let retained_point_floor = 4 * TRACE_ROWS * RESIDUE_COUNT * 256;
    assert!(verifier_work_bound < retained_point_floor);
    for context in [None, Some(COMPLETE_CONTEXT)] {
        let air = CompactTransferAir::new(&statement(), context).unwrap();
        let plan = ProducerPlan::new(&air, limits()).unwrap();
        let public_allowance = plan.quotient.work_units - plan.replay.work_units;
        assert!(public_allowance >= retained_point_floor);
        assert!(public_allowance > verifier_work_bound);
        assert_eq!(
            quotient_and_self_check_work(plan.quotient.work_units, plan.replay.work_units).unwrap(),
            plan.quotient.work_units + public_allowance
        );
        let default = crate::backend::offline_compact::ProvingLimits::default();
        assert_eq!(
            default.max_segment_work_units,
            usize::try_from(1_u64 << 42).unwrap()
        );
        assert!(plan.work_units <= default.max_segment_work_units);
        // The previous duplicate alone explains the native preflight refusal.
        assert!(plan.work_units + plan.replay.work_units > default.max_segment_work_units);
        let mut rng = NoEntropy(0);
        assert!(plan.build_from_borrowed_for_test(&[], &mut rng).is_err());
        assert_eq!(rng.0, 0);
    }
}

#[test]
fn retained_device_pool_remains_charged_during_the_larger_cpu_quotient_phase() {
    let pool = crate::gpu_memory::METAL_POOL_MAX_CACHED_BYTES;
    let twiddles = crate::gpu_memory::METAL_TWIDDLE_PAYLOAD_ALLOWANCE;
    assert_eq!(
        active_phase_payload(2 * pool, pool + 8, pool + 16).unwrap(),
        3 * pool + twiddles
    );
    // A larger row/coefficient phase keeps its envelope; persistent public
    // root tables remain charged once outside the maximum in every case.
    assert_eq!(
        active_phase_payload(8, 3 * pool, 2 * pool).unwrap(),
        3 * pool + twiddles
    );
    assert_eq!(
        active_phase_payload(8, 2 * pool, 3 * pool).unwrap(),
        3 * pool + twiddles
    );
    assert!(active_phase_payload(usize::MAX, 0, 0).is_err());
}

#[test]
fn frontier_envelope_and_replayed_root_equality_are_explicit() {
    let queries = maximal_queries();
    let plans = OpeningPlans::new(&queries).unwrap();
    assert_eq!(plans.initial.work().siblings, 1283);
    assert_eq!(
        plans.rounds.each_ref().map(|p| p.work().siblings),
        [975, 667, 436, 205, 51]
    );
    assert!(
        plans
            .round_indices
            .iter()
            .all(|positions| positions.len() == QUERY_COUNT)
    );
    let first = Digest::from_bytes([11; 32]);
    let second = Digest::from_bytes([13; 32]);
    same_root(first, first).unwrap();
    assert!(same_root(first, second).is_err());
    let context = Context::new(b"whole producer scheduling regression").unwrap();
    let mut transcript = Transcript::new(context);
    assert!(fields(&mut transcript, CONSTRAINTS).is_err());
    assert!(fields(&mut transcript, 1).is_err());
}

#[test]
fn preflight_queries_are_distinct_and_maximal_under_every_linked_reduction() {
    use std::collections::BTreeSet;

    let queries = maximal_queries();
    assert_eq!(queries.len(), QUERY_COUNT);
    assert!(queries.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(queries.iter().all(|&index| index < LDE_ROWS));
    let plans = OpeningPlans::new(&queries).unwrap();
    for (leaves, plan) in super::super::deep_geometry::FRI_LENGTHS
        .into_iter()
        .zip(core::iter::once(&plans.initial).chain(plans.rounds.iter()))
    {
        let mut positions: BTreeSet<_> = queries.iter().map(|index| index % leaves).collect();
        assert_eq!(positions.len(), QUERY_COUNT);
        assert_eq!(
            positions.iter().copied().collect::<Vec<_>>(),
            plan.queried_indices()
        );
        let mut observed_siblings = 0;
        let mut observed_parents = 0;
        for _ in 0..leaves.ilog2() {
            observed_siblings += positions
                .iter()
                .filter(|&&index| !positions.contains(&(index ^ 1)))
                .count();
            positions = positions.into_iter().map(|index| index / 2).collect();
            observed_parents += positions.len();
        }
        // The independent binary-tree occupancy bound is attained at every
        // linked depth; a merely unique but clustered set undercharges work.
        let maximum_siblings = (0..leaves.ilog2())
            .map(|depth| QUERY_COUNT.min(1usize << depth))
            .sum::<usize>()
            - QUERY_COUNT
            + 1;
        assert_eq!(observed_siblings, maximum_siblings);
        assert_eq!(plan.work().siblings, maximum_siblings);
        assert_eq!(plan.work().parent_hashes, observed_parents);
        assert_eq!(positions.into_iter().collect::<Vec<_>>(), vec![0]);
    }
}

#[test]
fn canonical_output_writer_is_byte_exact_and_refuses_short_cap_before_output() {
    // Serializer-only fixture: empty vectors deliberately do not satisfy the
    // proof relation. Production construction preflights and verifies separately.
    let proof = DeepProof {
        row_root: Digest::default().into(),
        quotient_root: Digest::default().into(),
        fri_roots: Vec::new(),
        ood: OodAnswers {
            current: Vec::new(),
            next: Vec::new(),
            quotient: Vec::new(),
        },
        rows: Vec::new(),
        quotients: Vec::new(),
        row_siblings: Vec::new(),
        quotient_siblings: Vec::new(),
        rounds: Vec::new(),
        terminal: Vec::new(),
    };
    let expected = norito::encode_canonical(&proof).unwrap();
    assert_eq!(encode_bounded(&proof, expected.len()).unwrap(), expected);
    assert!(encode_bounded(&proof, expected.len() - 1).is_err());
    assert!(deep_proof::decode(&expected, deep_proof::PROOF_BYTE_TARGET).is_err());
}

#[test]
#[ignore = "explicit full 8M-row DEEP producer with retained public artifact; measure separately"]
fn complete_native_masked_deep_producer_roundtrip_and_statement_rejection() {
    complete_masked_producer(DigestExecutionV1::Cpu);
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
#[test]
#[ignore = "explicit complete 8M-row proof with required Metal leaves/lower parents; measure separately"]
fn complete_required_metal_masked_deep_producer_roundtrip_and_statement_rejection() {
    let _lane = crate::backend::acquire_gpu_lane();
    complete_masked_producer(DigestExecutionV1::Device(
        crate::Digest384GpuBackendV1::Metal,
    ));
}

fn complete_siblings() -> [[u32; 8]; 32] {
    core::array::from_fn(|level| {
        digest(u8::try_from(level + 17).expect("32 sibling levels offset by 17 fit in u8"))
    })
}

// Independent public fixture facts are derived before reading any artifact.
fn complete_statement() -> PublicStatement {
    let siblings = complete_siblings();
    let path = 0xa59c_71e3;
    let first = digest(1);
    let second = digest(2);
    let mut root = first;
    for (level, sibling) in siblings.iter().enumerate() {
        let (left, right) = if (path >> level) & 1 == 0 {
            (root, *sibling)
        } else {
            (*sibling, root)
        };
        let mut message = b"fastpq:v1:smt:node|".to_vec();
        for limb in left.into_iter().chain(right) {
            message.extend_from_slice(&limb.to_le_bytes());
        }
        root = limbs(iroha_crypto::Hash::new(message).as_ref());
    }
    PublicStatement {
        updates: [
            PublicUpdate {
                old_leaf: first,
                new_leaf: second,
                path,
            },
            PublicUpdate {
                old_leaf: second,
                new_leaf: first,
                path,
            },
        ],
        old_root: root,
        new_root: root,
    }
}

fn complete_masked_producer(execution: DigestExecutionV1) {
    let (statement, air, proof, receipt) = build_complete_masked_proof(execution);
    assert_complete_proof_controls(&statement, &air, &proof);
    diagnostic_artifact::mark_controls_passed(&receipt).unwrap();
}

#[test]
#[ignore = "authentic full q77 seeded proof generation and relation controls; golden pin review remains required"]
fn generate_current_seeded_proof_for_review_with_all_relation_controls() {
    let (statement, air, proof, receipt) = build_complete_masked_proof(DigestExecutionV1::Cpu);
    assert_current_complete_proof_controls(&statement, &air, &proof);
    eprintln!(
        "q77 current relation controls passed; golden pins still require review; receipt={}",
        receipt.display()
    );
}

fn build_complete_masked_proof(
    execution: DigestExecutionV1,
) -> (
    PublicStatement,
    CompactTransferAir,
    Vec<u8>,
    std::path::PathBuf,
) {
    use crate::backend::compact_protocol::FixedAir as _;
    use crate::gadgets::compact_smt_air::PhysicalSmtWitness;
    // Required-device failure must precede the diagnostic's private witness too.
    super::super::deep_leaf_batch::preflight_execution(execution).unwrap();
    let statement = complete_statement();
    let siblings = complete_siblings();
    let air = CompactTransferAir::new(&statement, Some(COMPLETE_CONTEXT)).unwrap();
    let defaults = crate::backend::offline_compact::ProvingLimits::default();
    let plan = ProducerPlan::new(
        &air,
        ProducerLimits {
            digest_execution: execution,
            work: work(
                defaults.max_segment_charge_bytes,
                defaults.max_segment_work_units,
            ),
            max_hash_calls: defaults.max_segment_work_units,
            max_proof_bytes: deep_proof::PROOF_BYTE_TARGET,
        },
    )
    .unwrap();
    eprintln!(
        "complete DEEP attempt bound: payload={}, work={}, hashes={}",
        plan.payload_bytes, plan.work_units, plan.hash_calls
    );
    let witness = PhysicalSmtWitness::from_inputs(&statement, &[siblings, siblings]).unwrap();
    let columns = OwnedTraceSource::from_rows(witness.rows()).unwrap();
    drop(witness);
    let mut rng = StdRng::from_seed([83; 32]);
    let charges = (plan.payload_bytes, plan.work_units, plan.hash_calls);
    let started = std::time::Instant::now();
    let proof = plan.build(columns, &mut rng).unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "complete fixed-SMT DEEP proof: bytes={}; build_and_self_check_seconds={:.3}; proof_hash={}",
        proof.len(),
        elapsed,
        iroha_crypto::Hash::new(&proof),
    );
    // Retain only public outputs before later resource/golden/verifier assertions.
    let receipt = diagnostic_artifact::retain(
        &proof,
        air.statement_bytes(),
        COMPLETE_CONTEXT,
        elapsed,
        charges,
    )
    .unwrap();
    (statement, air, proof, receipt)
}

fn assert_complete_proof_controls(
    statement: &PublicStatement,
    air: &CompactTransferAir,
    proof: &[u8],
) {
    assert_current_complete_proof_controls(statement, air, proof);
    assert_eq!(
        proof.len(),
        COMPLETE_BYTES,
        "reviewed q77 complete seeded proof byte length"
    );
    assert_eq!(
        iroha_crypto::Hash::new(proof).to_string(),
        COMPLETE_HASH,
        "reviewed q77 complete seeded proof bytes"
    );
}

fn assert_current_complete_proof_controls(
    statement: &PublicStatement,
    air: &CompactTransferAir,
    proof: &[u8],
) {
    assert!(proof.len() <= deep_proof::MAX_FRAME_BYTES);
    assert_eq!(
        deep_engine::verify(air, proof, deep_proof::PROOF_BYTE_TARGET)
            .unwrap()
            .air_evaluations,
        1
    );
    assert!(deep_engine::verify(air, proof, proof.len() - 1).is_err());
    let other = CompactTransferAir::new(
        statement,
        Some(b"different authoritative statement context"),
    )
    .unwrap();
    assert!(deep_engine::verify(&other, proof, deep_proof::PROOF_BYTE_TARGET).is_err());
    let mut altered = proof.to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(deep_engine::verify(air, &altered, deep_proof::PROOF_BYTE_TARGET).is_err());
}

// TODO: Add actual owned Keccak SIMD/Metal/CUDA batch measurements and complete
// proof parity. Retired Poseidon continuations cannot measure this profile.
fn check_default_policy_plan(relation: &impl DeepRelation) {
    use crate::backend::{
        compact_protocol::FixedAir,
        offline_compact::{ProvingLimits, VerificationLimits},
    };
    let proving = ProvingLimits::default();
    let verification = VerificationLimits::default();
    // The facade's own mapping of the default policies to the engine limits.
    let limits = ProducerLimits::for_segment(
        &proving,
        &VerifierLimits::for_segment(
            verification.bundle.segment,
            verification.max_segment_decode_allocation_charges,
        ),
    );
    assert_eq!(limits.digest_execution, proving.digest_execution);
    assert_eq!(
        (limits.work.max_payload_bytes, limits.work.max_work_units),
        (
            proving.max_segment_charge_bytes,
            proving.max_segment_work_units
        )
    );
    assert_eq!(limits.max_hash_calls, proving.max_segment_work_units);
    assert_eq!(
        limits.max_proof_bytes,
        verification.bundle.segment.max_proof_bytes
    );
    let plan = ProducerPlan::new(relation, limits).unwrap();
    assert!(plan.payload_bytes <= proving.max_segment_charge_bytes);
    // Preserve the existing resource boundary. Admission must cover the
    // actual replay and additional quotient/commitment work within it.
    assert_eq!(
        proving.max_segment_work_units,
        usize::try_from(1_u64 << 42).unwrap()
    );
    assert!(plan.work_units > plan.replay.work_units);
    assert!(plan.work_units <= proving.max_segment_work_units);
    assert!(plan.hash_calls <= proving.max_segment_work_units);
    assert_eq!(
        plan.binding
            .hash_parent(Oracle::Row, 1, 0, Digest::default(), Digest::default())
            .unwrap(),
        Context::for_relation(relation)
            .unwrap()
            .hash_parent(Oracle::Row, 1, 0, Digest::default(), Digest::default())
            .unwrap()
    );
    assert_ne!(
        relation.schema().identity,
        relation.deep_relation().schema().identity
    );
    assert_ne!(
        plan.binding
            .hash_parent(Oracle::Row, 1, 0, Digest::default(), Digest::default())
            .unwrap(),
        Context::for_relation(relation.deep_relation())
            .unwrap()
            .hash_parent(Oracle::Row, 1, 0, Digest::default(), Digest::default())
            .unwrap()
    );
    for limited in [
        ProducerLimits {
            work: WorkLimits {
                max_payload_bytes: plan.payload_bytes - 1,
                ..limits.work
            },
            ..limits
        },
        ProducerLimits {
            work: WorkLimits {
                max_work_units: plan.work_units - 1,
                ..limits.work
            },
            ..limits
        },
        ProducerLimits {
            max_hash_calls: plan.hash_calls - 1,
            ..limits
        },
    ] {
        assert!(ProducerPlan::new(relation, limited).is_err());
    }
    let mut rng = NoEntropy(0);
    assert!(plan.build_from_borrowed_for_test(&[], &mut rng).is_err());
    assert_eq!(rng.0, 0);
}

#[test]
fn default_policies_preflight_quantity_relations_without_private_columns_or_entropy() {
    use crate::{
        ProofSemantics,
        backend::{
            compact_axt_batch::AxtTransferBatch,
            compact_axt_context::tests::Fixture,
            compact_public_api::AxtVerificationContext,
            compact_public_batch::{BatchContextLimits, PublicTransferBatch},
            deep_relation::tests as relation_fixture,
        },
        gadgets::public_transfer_statement::{
            PublicTransferLimits, prepare_quantity_public_transfers,
        },
    };

    // This fixture constructs only public transfer facts. It never materializes
    // touched-tree paths, a physical witness, coefficient matrices or an LDE.
    let fixture = Fixture::multiple(2, true);
    for semantics in [
        ProofSemantics::StateTransition,
        ProofSemantics::AxtTransferClaim,
    ] {
        let narrow = fixture.prepare(semantics);
        let (rows, claims, inputs) = relation_fixture::quantity_copy(&narrow);
        let prepared = prepare_quantity_public_transfers(
            &rows,
            &claims,
            inputs,
            semantics,
            PublicTransferLimits::default(),
        )
        .unwrap();
        let expected = relation_fixture::expected(&prepared);
        let roots = [inputs.old_root];
        if semantics == ProofSemantics::StateTransition {
            let batch = PublicTransferBatch::new(
                &prepared,
                &expected,
                &roots,
                BatchContextLimits::default(),
            )
            .unwrap();
            for index in 0..batch.segment_count() {
                check_default_policy_plan(&batch.segment(index).unwrap());
            }
        } else {
            let batch = AxtTransferBatch::new(
                &prepared,
                &expected,
                &roots,
                AxtVerificationContext {
                    binding: &fixture.binding,
                    metadata: fixture.metadata(),
                    mirrors: fixture.outer,
                    remote_spend_claims: fixture.remote.as_deref(),
                },
                BatchContextLimits::default(),
            )
            .unwrap();
            for index in 0..batch.segment_count() {
                check_default_policy_plan(&batch.segment(index).unwrap());
            }
        }
    }
}

#[test]
fn keccak_work_ledger_counts_trees_queries_transcripts_and_fixed_cold_readiness() {
    let binding = Context::new(b"complete Keccak ledger").unwrap();
    let plans = OpeningPlans::new(&maximal_queries()).unwrap();
    let permutations = keccak_permutation_charges(&binding, &plans).unwrap();
    let (row_leaf, row_parent) = binding.tree_permutations(Oracle::Row).unwrap();
    let row_only = LDE_ROWS * row_leaf + (LDE_ROWS - 1) * row_parent;
    assert!(permutations > row_only);
    assert!(
        permutations * 8192 < (1usize << 42),
        "Keccak alone must fit unchanged complete-work ceiling: {permutations}"
    );
    println!(
        "deep_keccak_permutations={permutations}; deep_keccak_work_units={}",
        permutations * 8192
    );
}
