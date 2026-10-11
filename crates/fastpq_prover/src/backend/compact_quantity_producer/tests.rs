//! Producer admission boundaries and explicit complete public-API proof coverage.

use std::cell::Cell;

use super::*;
use crate::backend::{
    compact_bundle::execution_effect::{
        self as effect_bundle, EffectBundleWire as BundleWire, EffectVerificationInputs,
        EffectVerificationLimits,
    },
    compact_execution_effect_batch::{EffectBatchLimits, ExecutionEffectBatch},
    compact_model_statement::candidate_artifact::effect_test_support::{
        self as effect_support, EffectFixture,
    },
};
use crate::gadgets::public_transfer_statement::execution_effect::{
    SourceExecutionEffectStatement, prepare_source_execution_effect_view,
};
use crate::test_producer_funding::{funding, prove_quantity_axt_artifact};
use crate::{
    VerifyLimits,
    backend::deep_geometry::QUERY_COUNT,
    backend::{
        compact_prover_resources::segment_charge,
        compact_quantity_tests::{QuantityCase, QuantityFixture},
    },
    gadgets::{
        compact_smt_air::{COLUMN_COUNT, PHYSICAL_ROW_COUNT},
        public_transfer_statement::{PublicTransferLimits, TransferSmtBuildLimits},
    },
    offline_compact::{
        BundleVerificationLimits, execution_effect_profile_id, quantity_ordinary_allocation_bytes,
        verify_quantity_axt_artifact,
    },
};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_data_model::fastpq::{
    FastpqArtifactIdentityDescriptionV1, FastpqAxtPreProofMirrorsV1, FastpqAxtPublicMetadataV1,
    FastpqCommitmentDescriptionV1, FastpqCompactArtifactDecodeLimits, FastpqCompactProfileIdV1,
    FastpqOrdinaryCompactArtifactV1, FastpqProofKindV1,
};
use norito::core::DecodeLimits;
use sha2::{Digest as _, Sha256};

fn policy() -> VerificationLimits {
    VerificationLimits {
        transport: FastpqCompactArtifactDecodeLimits {
            max_wire_bytes: 1024 * 1024,
            max_bundle_frame_bytes: 1024 * 1024,
            norito: DecodeLimits::new(
                20 * 1024 * 1024,
                20 * 1024 * 1024,
                25 * 1024 * 1024,
                96 * 1024 * 1024,
                32,
            ),
        },
        public_statement: PublicTransferLimits::default(),
        bundle: BundleVerificationLimits {
            max_segments: 2,
            max_wire_bytes: 1024 * 1024,
            max_total_segment_bytes: 1024 * 1024,
            max_total_statement_bytes: 512 * 1024,
            max_total_queries: 2 * QUERY_COUNT,
            max_total_decode_allocation_charges: 128 * 1024 * 1024,
            segment: VerifyLimits {
                max_proof_bytes: 512 * 1024,
                max_queries: QUERY_COUNT,
                ..VerifyLimits::default()
            },
        },
        max_segment_decode_allocation_charges: 64 * 1024 * 1024,
        total_decode: DecodeLimits::new(
            20 * 1024 * 1024,
            20 * 1024 * 1024,
            30 * 1024 * 1024,
            192 * 1024 * 1024,
            32,
        ),
    }
}

fn proving() -> ProvingLimits {
    ProvingLimits {
        digest_execution: crate::DigestExecutionV1::Cpu,
        private_smt: TransferSmtBuildLimits::for_update_limit(4).unwrap(),
        max_total_trace_cells: 2 * COLUMN_COUNT * PHYSICAL_ROW_COUNT,
        max_segment_work_units: usize::try_from(1_u64 << 46).unwrap(),
        max_segment_charge_bytes: 2 * 1024 * 1024 * 1024,
    }
}

fn fixture() -> QuantityFixture {
    let (fixture, private) = QuantityFixture::new(QuantityCase::MixedScale, 2);
    drop(private);
    fixture
}

fn expected(statement: &FastpqPublicTransferStatementV1) -> ExpectedStatement {
    ExpectedStatement {
        inputs: statement.public_inputs,
        ordering_hash: statement.ordering_hash,
        public_statement_digest: Hash::new(norito::encode_canonical(statement).unwrap()).into(),
    }
}

/// Finite synthetic fixture funding only; returned verification summaries retain no
/// charged preparation backing. Production always receives its original owner.
fn with_effect_credit<T>(
    fixture: &EffectFixture,
    consume: impl FnOnce(&AllocationBudget, &mut AllocationReservation) -> T,
) -> T {
    let demand = quantity_ordinary_allocation_bytes(
        &fixture.statement.effects,
        proving(),
        &effect_support::fixture::limits(policy()),
    )
    .unwrap();
    let budget = AllocationBudget::new(demand);
    let mut reservation = budget.try_reserve_bytes(demand).unwrap();
    let result = consume(&budget, &mut reservation);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    result
}

fn verify_effect_public(
    fixture: &EffectFixture,
    bytes: &[u8],
    public: ExpectedStatement,
    limits: &VerificationLimits,
) -> std::result::Result<
    crate::offline_compact::VerifiedArtifact,
    crate::offline_compact::VerificationError,
> {
    let mut expected = fixture.expected();
    expected.statement.public_inputs = public.inputs;
    expected.statement.statement_digest =
        Hash::from_marked_bytes(public.public_statement_digest).unwrap();
    fixture.verify_expected(bytes, expected, *limits)
}

/// Test dispatch calls each actual producer's preflight and final encoder. No
/// accepted wire, constraint or admission calculation is reimplemented here.
enum TestArtifact<'a> {
    Axt(&'a FastpqPublicTransferStatementV1, ExpectedAxtContext<'a>),
    Effect(&'a EffectFixture),
}
impl<'a> TestArtifact<'a> {
    fn new(
        statement: &'a FastpqPublicTransferStatementV1,
        effect: &'a EffectFixture,
        context: Option<ExpectedAxtContext<'a>>,
    ) -> Self {
        context.map_or(Self::Effect(effect), |context| {
            Self::Axt(statement, context)
        })
    }
    fn preflight(&self, count: usize, limits: &VerificationLimits) -> Result<()> {
        match self {
            Self::Axt(statement, context) => {
                Artifact::new(statement, *context).preflight(count, limits)
            }
            Self::Effect(effect) => {
                let mut empty;
                let effect = if count == 0 {
                    // The new producer derives its count from the original tape.
                    // Exercise its actual empty-tape preflight, not a modeled error.
                    empty = EffectFixture::clone(effect);
                    empty.statement.effects.effects.clear();
                    &empty
                } else {
                    effect
                };
                execution_effect::preflight_for_test(
                    &SourceExecutionEffectStatement::from_owned(&effect.statement),
                    effect.expected(),
                    proving(),
                    &effect_support::fixture::limits(*limits),
                )
                .map(|_| ())
            }
        }
    }
    fn empty_frame_len(&self) -> usize {
        match self {
            Self::Axt(statement, context) => {
                norito::core::encoded_frame_len(&Artifact::new(statement, *context).0).unwrap()
            }
            Self::Effect(effect) => {
                norito::core::encoded_frame_len(&effect.artifact(Vec::new())).unwrap()
            }
        }
    }
    fn finish(&self, frame: Vec<u8>, limits: &VerificationLimits) -> Result<Vec<u8>> {
        match self {
            Self::Axt(statement, context) => {
                Artifact::new(statement, *context).finish(frame, limits)
            }
            Self::Effect(effect) => execution_effect::encode_artifact(
                &SourceExecutionEffectStatement::from_owned(&effect.statement),
                &effect.source,
                &frame,
                &effect_support::fixture::limits(*limits),
            ),
        }
    }
}

fn assert_valid_effect_context(effect: &EffectFixture, roots: &[[u8; 32]]) {
    with_effect_credit(effect, |budget, credit| {
        let limits = effect_support::fixture::limits(policy());
        let batch = ExecutionEffectBatch::new(
            &SourceExecutionEffectStatement::from_owned(&effect.statement),
            &effect.source,
            effect.facts(),
            roots,
            EffectBatchLimits {
                public: limits.public_policy(),
                context: BatchContextLimits {
                    max_segments: 2,
                    max_total_statement_bytes: limits.bundle.max_total_statement_bytes,
                },
            },
            budget,
            credit,
        )
        .unwrap();
        drop(batch);
    });
}

fn axt_fields(
    fixture: &QuantityFixture,
) -> (FastpqAxtPublicMetadataV1, FastpqAxtPreProofMirrorsV1) {
    let context = fixture.context();
    let metadata = context.metadata;
    let mirrors = context.mirrors;
    (
        FastpqAxtPublicMetadataV1 {
            source_transfer_occurrences: metadata.source_transfer_occurrences.to_vec(),
            parameter: metadata.parameter.to_owned(),
            entry_hash: metadata.entry_hash.try_into().unwrap(),
            committed_amount: metadata.committed_amount.map(|b| b.try_into().unwrap()),
            expiry_slot: metadata.expiry_slot.try_into().unwrap(),
            manifest_root: metadata.manifest_root.try_into().unwrap(),
            da_commitment: metadata.da_commitment.try_into().unwrap(),
        },
        FastpqAxtPreProofMirrorsV1 {
            dsid: mirrors.dsid,
            manifest_root: mirrors.manifest_root,
            da_commitment: mirrors.da_commitment,
            committed_amount: mirrors.committed_amount,
            expiry_slot: mirrors.expiry_slot,
        },
    )
}

fn assert_limit(result: &Result<impl std::fmt::Debug>, name: &str, actual: usize, max: usize) {
    assert!(
        matches!(*result, Err(Error::VerifierLimitExceeded { limit, actual: got, max: cap })
        if limit == name && got == actual && cap == max)
    );
}

#[test]
fn exclusive_admission_reports_busy_releases_and_recovers_poison_locally() {
    // This mutex is private to the test, so neither the global producer nor a
    // parallel full-proof diagnostic can interfere with these assertions.
    let mutex = Mutex::new(());
    let first = acquire(&mutex).unwrap();
    assert!(matches!(acquire(&mutex), Err(ProvingError::Busy)));
    drop(first);
    drop(acquire(&mutex).unwrap());
    std::thread::scope(|scope| {
        let result = scope
            .spawn(|| {
                let _held = mutex.lock().unwrap();
                panic!("deliberately poison only this test's admission mutex");
            })
            .join();
        assert!(result.is_err());
    });
    assert!(mutex.is_poisoned());
    let recovered = acquire(&mutex).unwrap();
    assert!(matches!(acquire(&mutex), Err(ProvingError::Busy)));
    drop(recovered);
    drop(acquire(&mutex).unwrap());
}

#[test]
fn byte_and_work_arithmetic_rejects_overflow_without_saturating() {
    assert_eq!(add(usize::MAX, 0).unwrap(), usize::MAX);
    assert_eq!(mul(usize::MAX, 1).unwrap(), usize::MAX);
    assert_eq!(mul(usize::MAX, 0).unwrap(), 0);
    assert!(
        matches!(add(usize::MAX, 1), Err(Error::TransferInvariant { details })
        if details == "producer byte count overflows")
    );
    assert!(
        matches!(mul(usize::MAX, 2), Err(Error::TransferInvariant { details })
        if details == "producer work count overflows")
    );
}

#[test]
fn complete_statement_caps_are_inclusive_and_fail_before_public_preparation() {
    // This shared transfer preflight now belongs exclusively to the AXT producer.
    // Complete-effect ordinary preflight is exercised through its actual child hook below.
    let statement = fixture().model();
    let expected = expected(&statement);
    let mut exact = policy();
    exact.public_statement.max_rows = statement.transitions.len();
    exact.public_statement.max_transcripts = statement.transcripts.len();
    exact.public_statement.max_deltas = 2;
    exact.public_statement.max_public_bytes = norito::core::encoded_frame_len(&statement).unwrap();
    exact.bundle.max_segments = 2;
    exact.bundle.max_total_queries = 2 * QUERY_COUNT;
    exact.bundle.segment.max_queries = QUERY_COUNT;
    exact.bundle.segment.max_proof_bytes = SHARED_FRAME_BOUND;
    exact.bundle.max_total_segment_bytes = 2 * SHARED_FRAME_BOUND;
    let mut work = proving();
    work.max_segment_charge_bytes = segment_charge(0, SHARED_FRAME_BOUND).unwrap();
    assert_eq!(
        check_statement(&statement, expected, work, exact).unwrap(),
        2
    );

    for (name, actual) in [
        ("max_public_transfer_rows", statement.transitions.len()),
        (
            "max_public_transfer_transcripts",
            statement.transcripts.len(),
        ),
        ("max_public_transfer_deltas", 2),
        ("max_bundle_segments", 2),
        ("max_queries", QUERY_COUNT),
        ("max_bundle_queries", 2 * QUERY_COUNT),
        ("max_proof_bytes", SHARED_FRAME_BOUND),
        ("max_bundle_segment_bytes", 2 * SHARED_FRAME_BOUND),
        ("max_compact_prover_trace_cells", work.max_total_trace_cells),
        (
            "max_compact_prover_segment_charge_bytes",
            work.max_segment_charge_bytes,
        ),
        (
            "max_compact_producer_statement_bytes",
            exact.public_statement.max_public_bytes,
        ),
    ] {
        let mut limited = exact;
        let mut limited_work = work;
        let cap = actual - 1;
        match name {
            "max_public_transfer_rows" => limited.public_statement.max_rows = cap,
            "max_public_transfer_transcripts" => limited.public_statement.max_transcripts = cap,
            "max_public_transfer_deltas" => limited.public_statement.max_deltas = cap,
            "max_bundle_segments" => limited.bundle.max_segments = cap,
            "max_queries" => limited.bundle.segment.max_queries = cap,
            "max_bundle_queries" => limited.bundle.max_total_queries = cap,
            "max_proof_bytes" => limited.bundle.segment.max_proof_bytes = cap,
            "max_bundle_segment_bytes" => limited.bundle.max_total_segment_bytes = cap,
            "max_compact_prover_trace_cells" => limited_work.max_total_trace_cells = cap,
            "max_compact_prover_segment_charge_bytes" => {
                limited_work.max_segment_charge_bytes = cap
            }
            "max_compact_producer_statement_bytes" => {
                limited.public_statement.max_public_bytes = cap
            }
            _ => unreachable!(),
        }
        assert_limit(
            &check_statement(&statement, expected, limited_work, limited),
            name,
            actual,
            cap,
        );
    }
}

#[test]
fn masked_replay_work_budget_rejects_before_statement_digest_or_private_rows() {
    let statement = fixture().model();
    let mut expected = expected(&statement);
    expected.public_statement_digest[0] ^= 1;
    let minimum = crate::backend::compact_prover_resources::replay_plan()
        .unwrap()
        .work_units;
    for cap in [0, minimum - 1] {
        let mut limits = proving();
        limits.max_segment_work_units = cap;
        assert_limit(
            &check_statement(&statement, expected, limits, policy()),
            "max_compact_prover_segment_work_units",
            minimum,
            cap,
        );
    }
    let mut limits = proving();
    limits.max_segment_work_units = minimum;
    assert!(matches!(
        check_statement(&statement, expected, limits, policy()),
        Err(Error::PublicIoMismatch {
            field: "compact_public_statement_digest"
        })
    ));
}

#[test]
fn producer_binds_original_headers_and_rejects_empty_bundles() {
    let statement = fixture().model();
    let expected = expected(&statement);
    for authority in [true, false] {
        let mut changed = statement.clone();
        if authority {
            changed.transcripts[0].authority_digest = Hash::new(b"different original authority");
        } else {
            changed.transcripts[0].batch_hash = Hash::new(b"different original batch");
        }
        assert!(matches!(
            check_statement(&changed, expected, proving(), policy()),
            Err(Error::PublicIoMismatch {
                field: "compact_public_statement_digest"
            })
        ));
    }
    let mut empty = statement;
    empty.transcripts.clear();
    assert!(matches!(
        check_statement(&empty, expected, proving(), policy()),
        Err(Error::TransferInvariant { details }) if details.contains("nonempty complete bundle")
    ));
}

#[test]
fn impossible_decoder_budget_rejects_before_statement_digest_work() {
    let statement = fixture().model();
    let mut expected = expected(&statement);
    expected.public_statement_digest[0] ^= 1;
    let mut limited = policy();
    limited.max_segment_decode_allocation_charges = 0;
    assert_limit(
        &check_statement(&statement, expected, proving(), limited),
        "max_compact_producer_segment_decode_allocation_charges",
        QUERY_COUNT
            * crate::backend::compact_public_columns::COMMITTED_COLUMN_COUNT
            * size_of::<u64>(),
        0,
    );
    assert!(matches!(
        check_statement(&statement, expected, proving(), policy()),
        Err(Error::PublicIoMismatch {
            field: "compact_public_statement_digest"
        })
    ));
}

#[test]
fn fixed_shape_and_carrier_policy_reject_before_statement_digest_work() {
    let statement = fixture().model();
    let mut expected = expected(&statement);
    expected.public_statement_digest[0] ^= 1;
    let resources = quantity_artifact_resources(2, 0).unwrap();
    for (name, minimum) in [
        (
            "max_air_row_values",
            crate::backend::compact_public_columns::COMMITTED_COLUMN_COUNT,
        ),
        ("max_fri_layers", 6),
        ("max_query_path_len", 23),
        ("max_fri_round_values", 16),
        (
            "max_bundle_wire_bytes",
            resources.maximum_bundle_frame_bytes,
        ),
        (
            "max_compact_producer_bundle_bytes",
            resources.maximum_bundle_frame_bytes,
        ),
    ] {
        let mut limited = policy();
        let cap = minimum - 1;
        match name {
            "max_air_row_values" => limited.bundle.segment.max_air_row_values = cap,
            "max_fri_layers" => limited.bundle.segment.max_fri_layers = cap,
            "max_query_path_len" => limited.bundle.segment.max_query_path_len = cap,
            "max_fri_round_values" => limited.bundle.segment.max_fri_round_values = cap,
            "max_bundle_wire_bytes" => limited.bundle.max_wire_bytes = cap,
            "max_compact_producer_bundle_bytes" => limited.transport.max_bundle_frame_bytes = cap,
            _ => unreachable!(),
        }
        assert_limit(
            &check_statement(&statement, expected, proving(), limited),
            name,
            minimum,
            cap,
        );
    }
}

#[test]
fn artifact_byte_preflight_and_final_encoding_keep_inclusive_bounds() {
    let f = fixture();
    let statement = f.model();
    let (metadata, mirrors) = axt_fields(&f);
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let effect = EffectFixture::from_transfer_facts(&statement);
    for axt in [None, Some(context)] {
        let artifact = TestArtifact::new(&statement, &effect, axt);
        assert!(matches!(
            artifact.preflight(0, &policy()),
            Err(Error::TransferInvariant { .. })
        ));
        let carrier = 1024 + 64 + 2 * (SHARED_FRAME_BOUND + 32);
        let empty = artifact.empty_frame_len();
        let total = empty + carrier + 32;
        let mut exact = policy();
        exact.bundle.max_wire_bytes = carrier;
        exact.transport.max_bundle_frame_bytes = carrier;
        exact.transport.max_wire_bytes = total;
        artifact.preflight(2, &exact).unwrap();
        for (name, actual) in [
            ("max_bundle_wire_bytes", carrier),
            ("max_compact_producer_bundle_bytes", carrier),
            ("max_compact_producer_artifact_bytes", total),
        ] {
            let mut limited = exact;
            match name {
                "max_bundle_wire_bytes" => limited.bundle.max_wire_bytes -= 1,
                "max_compact_producer_bundle_bytes" => {
                    limited.transport.max_bundle_frame_bytes -= 1
                }
                _ => limited.transport.max_wire_bytes -= 1,
            }
            assert_limit(&artifact.preflight(2, &limited), name, actual, actual - 1);
        }
        let bytes = TestArtifact::new(&statement, &effect, axt)
            .finish(vec![1, 2, 3], &policy())
            .unwrap();
        let mut exact = policy();
        exact.transport.max_bundle_frame_bytes = 3;
        exact.transport.max_wire_bytes = bytes.len();
        assert_eq!(
            TestArtifact::new(&statement, &effect, axt)
                .finish(vec![1, 2, 3], &exact)
                .unwrap(),
            bytes
        );
        exact.transport.max_wire_bytes -= 1;
        assert_limit(
            &TestArtifact::new(&statement, &effect, axt).finish(vec![1, 2, 3], &exact),
            "max_compact_producer_artifact_bytes",
            bytes.len(),
            bytes.len() - 1,
        );
    }
}

#[test]
fn supplied_root_mismatch_is_not_replaced_with_locally_derived_roots() {
    let f = fixture();
    for old in [true, false] {
        let mut effect = EffectFixture::from_transfer_facts(&f.model());
        if old {
            effect.statement.public_inputs.old_root = Hash::prehashed([17; 32]).into();
        } else {
            effect.statement.public_inputs.new_root = Hash::prehashed([19; 32]).into();
        }
        // Invoke the same original preparation/tree-root check as the producer,
        // before any global producer lock or physical trace expansion.
        let result = with_effect_credit(&effect, |budget, credit| {
            let prepared = prepare_source_execution_effect_view(
                &SourceExecutionEffectStatement::from_owned(&effect.statement),
                &effect.source,
                effect.facts(),
                effect_support::fixture::limits(policy()).public_policy(),
                budget,
                credit,
            )?;
            prepared.build_smt_witnesses(proving().private_smt, budget, credit)
        });
        assert!(
            matches!(result, Err(Error::TransferInvariant { details }) if details.contains("root")),
            "producer must reject the supplied endpoint"
        );
    }
}

#[test]
fn axt_context_mismatch_precedes_even_private_tree_work() {
    let f = fixture();
    let statement = f.model();
    let expected = expected(&statement);
    let (metadata, mut mirrors) = axt_fields(&f);
    mirrors.manifest_root[0] ^= 1;
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let mut work = proving();
    work.private_smt = TransferSmtBuildLimits::for_update_limit(0).unwrap();
    let (budget, mut reservation) = funding(statement.transitions.len());
    let result = prepare_and_prove(
        &f.prepare(ProofSemantics::AxtTransferClaim),
        &statement,
        expected,
        context,
        work,
        policy(),
        &budget,
        &mut reservation,
    );
    assert!(matches!(result, Err(Error::InvalidAxtBinding { details })
        if details.contains("manifest_root")));
}

#[test]
fn all_segment_contexts_are_checked_before_the_first_physical_witness() {
    let (f, private) = QuantityFixture::new(QuantityCase::MixedScale, 2);
    let prepared = f.prepare(ProofSemantics::AxtTransferClaim);
    let roots = [private.pairs()[0][1].root_after];
    let batch = AxtTransferBatch::new(
        &prepared,
        &f.expected(),
        &roots,
        f.context(),
        BatchContextLimits {
            max_segments: 2,
            max_total_statement_bytes: 512 * 1024,
        },
    )
    .unwrap();
    let mut bad_private = private.pairs().to_vec();
    bad_private[0][0].path_bits[0] ^= 1;
    let calls = Cell::new(0);
    let result = segments(
        batch.statements(),
        &bad_private,
        |ordinal| {
            calls.set(calls.get() + 1);
            if ordinal == 1 {
                return Err(invalid("second segment rejected before any witness"));
            }
            batch.segment(ordinal)
        },
        proving(),
        policy(),
    );
    assert!(matches!(result, Err(Error::TransferInvariant { details })
        if details == "second segment rejected before any witness"));
    assert_eq!(calls.get(), 2);

    calls.set(0);
    let result = segments(
        batch.statements(),
        &bad_private[..1],
        |ordinal| {
            calls.set(calls.get() + 1);
            batch.segment(ordinal)
        },
        proving(),
        policy(),
    );
    assert!(matches!(result, Err(Error::TransferInvariant { details })
        if details.contains("pair count differs")));
    assert_eq!(calls.get(), 0);
}

#[test]
fn malformed_private_paths_fail_before_physical_column_allocation() {
    let (f, private) = QuantityFixture::new(QuantityCase::MixedScale, 1);
    let prepared = f.prepare(ProofSemantics::AxtTransferClaim);
    let statement = prepared.compact_statements(&[]).unwrap().remove(0);
    for wrong_path in [true, false] {
        let mut pair = private.pairs()[0].clone();
        if wrong_path {
            pair[0].path_bits[0] ^= 1;
        } else {
            pair[1].siblings.pop();
        }
        assert!(
            matches!(columns(&statement, &pair), Err(Error::TransferInvariant { details })
            if details.contains("private path differs"))
        );
    }
}

#[test]
#[ignore = "explicit fresh ordinary and AXT public producer proofs over two full-domain segments"]
fn public_producer_generates_complete_ordinary_and_axt_artifacts() {
    public_producer_with_execution(crate::DigestExecutionV1::Cpu);
}

#[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
#[test]
#[ignore = "actual Metal ordinary and AXT public producers over two full-domain segments each; no CPU substitution"]
fn actual_metal_public_producer_generates_complete_ordinary_and_axt_artifacts() {
    let _lane = crate::backend::acquire_gpu_lane();
    // Every segment inherits the required device selection; failed device work
    // cannot be replaced with CPU commitments by the public producer.
    public_producer_with_execution(crate::DigestExecutionV1::Device(
        crate::Digest384GpuBackendV1::Metal,
    ));
}

fn public_producer_with_execution(execution: crate::DigestExecutionV1) {
    // A single test keeps both requests sequential even when the harness uses
    // parallel test threads; the public producer intentionally rejects overlap.
    let f = fixture();
    let statement = f.model();
    let expected = expected(&statement);
    let (metadata, mirrors) = axt_fields(&f);
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let proving = ProvingLimits {
        digest_execution: execution,
        ..proving()
    };
    let effect = EffectFixture::from_transfer_facts(&statement);
    for is_axt in [false, true] {
        let route_expected = if is_axt {
            expected
        } else {
            effect.public_expectation()
        };
        let started = std::time::Instant::now();
        let bytes = if is_axt {
            prove_quantity_axt_artifact(&statement, expected, context, proving, policy())
        } else {
            effect.prove(proving, policy())
        }
        .unwrap();
        let prove_elapsed = started.elapsed();
        // Preserve the exact canonical public bytes before the independent
        // verifier, including when a later assertion fails.
        let label = if is_axt { "axt" } else { "ordinary" };
        let sha = format!("{:x}", Sha256::digest(&bytes));
        let path = retain_public_artifact(label, &bytes);
        let started = std::time::Instant::now();
        let verified = if is_axt {
            verify_quantity_axt_artifact(&bytes, expected, context, policy())
        } else {
            effect.verify(&bytes, policy())
        }
        .unwrap();
        let verify_elapsed = started.elapsed();
        assert_eq!(verified.expected_statement(), route_expected);
        assert_eq!(verified.segments(), 2);
        assert_eq!(verified.work().air_evaluations, 2);
        assert_eq!(verified.work().terminal_degree_checks, 2);
        assert_eq!(
            verified.identity().artifact_bytes,
            u64::try_from(bytes.len()).unwrap()
        );
        eprintln!(
            "quantity_public_producer={label}; digest_executor={execution:?}; bytes={}; sha256={sha}; proving_including_self_verification={prove_elapsed:?}; independent_verification={verify_elapsed:?}; work={:?}; retained={}",
            bytes.len(),
            verified.work(),
            path.display()
        );
    }
}

fn assert_internal_artifact_matches_public(
    bytes: &[u8],
    is_axt: bool,
    expected: ExpectedStatement,
    context: ExpectedAxtContext<'_>,
    effect: &EffectFixture,
    public: &crate::offline_compact::VerifiedArtifact,
    raw_bundle: &crate::backend::compact_bundle::VerifiedBundle,
) {
    use crate::backend::compact_model_statement::candidate_artifact::{
        ArtifactLimits, verify_bound_quantity_axt_artifact,
    };
    let limits = policy();
    let internal_limits = ArtifactLimits {
        transport: limits.transport,
        public_statement: limits.public_statement,
        bundle: limits.bundle.internal(),
        max_segment_decode_allocation_charges: limits.max_segment_decode_allocation_charges,
        total_decode: limits.total_decode,
    };
    let internal = if is_axt {
        verify_bound_quantity_axt_artifact(
            bytes,
            &expected.internal(),
            expected.public_statement_digest,
            context.internal(),
            internal_limits,
        )
    } else {
        effect_support::verify(bytes, effect, internal_limits)
    }
    .unwrap();
    // Preserve artifact-level equality independently of the existing direct
    // bundle/public work checks, including the complete canonical identity.
    assert_eq!(internal.identity(), public.identity());
    assert_eq!(internal.bundle(), raw_bundle);
}

fn retained_directory() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fastpq-production-validation")
}

fn retain_public_artifact(label: &str, bytes: &[u8]) -> std::path::PathBuf {
    use std::io::Write;
    assert!(bytes.len() <= policy().transport.max_wire_bytes);
    let directory = retained_directory();
    std::fs::create_dir_all(&directory).unwrap();
    let sha = format!("{:x}", Sha256::digest(bytes));
    let path = directory.join(format!("quantity-public-producer-deep-{label}-{sha}.bin"));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut output) => {
            output.write_all(bytes).unwrap();
            output.sync_all().unwrap();
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                u64::try_from(bytes.len()).unwrap()
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        Err(error) => panic!("retain public artifact: {error}"),
    }
    path
}

fn read_public_artifact(variable: &str, label: &str) -> Vec<u8> {
    use std::io::Read;
    let supplied = std::env::var_os(variable).unwrap_or_else(|| panic!("set {variable}"));
    let path = std::path::Path::new(&supplied).canonicalize().unwrap();
    assert_eq!(
        path.parent().unwrap(),
        retained_directory().canonicalize().unwrap()
    );
    let name = path.file_name().unwrap().to_str().unwrap();
    let sha = name
        .strip_prefix(&format!("quantity-public-producer-deep-{label}-"))
        .and_then(|suffix| suffix.strip_suffix(".bin"))
        .expect("use the SHA-addressed output of the DEEP public producer");
    assert!(sha.len() == 64 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let input = std::fs::File::open(path.as_path()).unwrap();
    let cap = policy().transport.max_wire_bytes;
    assert!(input.metadata().unwrap().len() <= u64::try_from(cap).unwrap());
    let mut bytes = Vec::new();
    input
        .take(u64::try_from(cap).unwrap() + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= cap);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha);
    bytes
}

fn raw_bundle_frame(wire: &BundleWire, is_axt: bool) -> Vec<u8> {
    if is_axt {
        norito::encode_canonical(&AxtBundleWire {
            version: wire.version,
            intermediate_roots: wire.intermediate_roots.clone(),
            segments: wire.segments.clone(),
        })
        .unwrap()
    } else {
        norito::encode_canonical(wire).unwrap()
    }
}

fn assert_deep_context_rejected(error: &crate::offline_compact::VerificationError) {
    assert!(
        matches!(error,
            crate::offline_compact::VerificationError::Verify(Error::InvalidTraceShape { details })
            if details == "DEEP out-of-domain AIR quotient identity does not hold"
                || details == "DEEP opening positions differ from the exact derived query set"
        ),
        "changed public context must reach its DEEP binding check: {error:?}"
    );
}

fn assert_valid_public_context(
    statement: &FastpqPublicTransferStatementV1,
    expected: ExpectedStatement,
    context: ExpectedAxtContext<'_>,
    roots: &[[u8; 32]],
) {
    with_prepared_quantity_statement(
        statement,
        &expected.internal(),
        ProofSemantics::AxtTransferClaim,
        policy().public_statement,
        |prepared| {
            AxtTransferBatch::new(
                prepared,
                &expected.internal(),
                roots,
                context.internal(),
                BatchContextLimits {
                    max_segments: 2,
                    max_total_statement_bytes: policy().bundle.max_total_statement_bytes,
                },
            )?;
            Ok(())
        },
    )
    .unwrap();
}

/// One captured artifact, its decoded bundle and its independent fixture expectations.
struct CapturedArtifact<'a> {
    is_axt: bool,
    statement: &'a FastpqPublicTransferStatementV1,
    effect: &'a EffectFixture,
    expected: ExpectedStatement,
    context: ExpectedAxtContext<'a>,
    bytes: Vec<u8>,
    frame: Vec<u8>,
    wire: BundleWire,
}

impl CapturedArtifact<'_> {
    fn wrap(&self, frame: Vec<u8>) -> Vec<u8> {
        TestArtifact::new(
            self.statement,
            self.effect,
            self.is_axt.then_some(self.context),
        )
        .finish(frame, &policy())
        .unwrap()
    }
    fn valid_context(&self, roots: &[[u8; 32]]) {
        if self.is_axt {
            assert_valid_public_context(self.statement, self.expected, self.context, roots);
        } else {
            assert_valid_effect_context(self.effect, roots);
        }
    }
    /// Verify `raw` against `expected` through the matching public entry point.
    fn verify(
        &self,
        raw: &[u8],
        expected: ExpectedStatement,
    ) -> std::result::Result<
        crate::offline_compact::VerifiedArtifact,
        crate::offline_compact::VerificationError,
    > {
        if self.is_axt {
            verify_quantity_axt_artifact(raw, expected, self.context, policy())
        } else {
            verify_effect_public(self.effect, raw, expected, &policy())
        }
    }

    /// Verify `raw` against the fixture expectation under explicit caller limits.
    fn verify_limits(
        &self,
        raw: &[u8],
        limits: &VerificationLimits,
    ) -> std::result::Result<
        crate::offline_compact::VerifiedArtifact,
        crate::offline_compact::VerificationError,
    > {
        if self.is_axt {
            verify_quantity_axt_artifact(raw, self.expected, self.context, *limits)
        } else {
            self.effect.verify(raw, *limits)
        }
    }
}

/// Decode the outer artifact and its inner bundle under the fixed transport policy.
fn decode_captured_bundle(
    bytes: &[u8],
    is_axt: bool,
    statement: &FastpqPublicTransferStatementV1,
    effect: &EffectFixture,
    profile: FastpqCompactProfileIdV1,
) -> (Vec<u8>, BundleWire) {
    let frame = if is_axt {
        let artifact = FastpqAxtCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            profile,
            policy().transport,
        )
        .unwrap();
        assert_eq!(&artifact.statement, statement);
        artifact.bundle_frame
    } else {
        let artifact = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            profile,
            policy().transport,
        )
        .unwrap();
        assert_eq!(&artifact.statement, &effect.statement);
        assert_eq!(&artifact.source, &effect.source);
        artifact.bundle_frame
    };
    let wire: BundleWire = if is_axt {
        let wire: AxtBundleWire =
            norito::decode_canonical_with_limits(&frame, policy().total_decode).unwrap();
        BundleWire {
            version: wire.version,
            intermediate_roots: wire.intermediate_roots,
            segments: wire.segments,
        }
    } else {
        norito::decode_canonical_with_limits(&frame, policy().total_decode).unwrap()
    };
    (frame, wire)
}

/// The verified summary and canonical identity describe exactly these bytes.
fn assert_captured_identity(
    captured: &CapturedArtifact<'_>,
    verified: &crate::offline_compact::VerifiedArtifact,
    profile: FastpqCompactProfileIdV1,
) {
    let (bytes, frame, wire) = (&captured.bytes, &captured.frame, &captured.wire);
    let expected = captured.expected;
    assert_eq!(verified.expected_statement(), expected);
    assert_eq!(verified.segments(), 2);
    assert_eq!(wire.segments.len(), 2);
    assert_eq!(verified.work().air_evaluations, 2);
    assert_eq!(verified.work().terminal_degree_checks, 2);
    assert_eq!(verified.work().transcripts, 2);
    assert_eq!(verified.bundle_frame_bytes(), frame.len());
    assert_eq!(
        verified.work().proof_bytes,
        wire.segments.iter().map(Vec::len).sum::<usize>()
    );
    let identity = verified.identity();
    assert_eq!(identity.profile_id, profile);
    assert_eq!(
        identity.proof_kind,
        if captured.is_axt {
            FastpqProofKindV1::AxtCompact
        } else {
            FastpqProofKindV1::OrdinaryCompact
        }
    );
    assert_eq!(
        identity.public_statement_digest,
        expected.public_statement_digest
    );
    assert_eq!(identity.artifact_digest, <[u8; 32]>::from(Hash::new(bytes)));
    assert_eq!(
        identity.inner_bundle_digest,
        <[u8; 32]>::from(Hash::new(frame))
    );
    assert_eq!(identity.artifact_bytes, u64::try_from(bytes.len()).unwrap());
    assert_ne!(identity.artifact_digest, identity.inner_bundle_digest);
    let FastpqCommitmentDescriptionV1::OrderedCompactAir(roots) = &identity.commitments else {
        panic!("quantity artifact must retain complete ordered AIR commitments")
    };
    assert_eq!(roots.segment_count, 2);
    assert_eq!(roots.segment_air_row_roots.len(), 2);
    assert_eq!(roots.segment_air_row_roots, verified.air_row_roots());
    assert_eq!(
        norito::decode_canonical::<FastpqArtifactIdentityDescriptionV1>(
            &norito::encode_canonical(identity).unwrap()
        )
        .unwrap(),
        *identity
    );

    let mut wrong = expected;
    wrong.public_statement_digest[0] ^= 1;
    assert!(matches!(
        captured.verify(bytes, wrong),
        Err(crate::offline_compact::VerificationError::Verify(
            Error::PublicIoMismatch {
                field: "compact_artifact_public_statement_digest"
            }
        ))
    ));
    wrong = expected;
    wrong.inputs.old_root[0] ^= 1;
    if captured.is_axt {
        assert!(matches!(
            captured.verify(bytes, wrong),
            Err(crate::offline_compact::VerificationError::Verify(
                Error::PublicIoMismatch {
                    field: "compact_model_public_io"
                }
            ))
        ));
    } else {
        assert!(matches!(captured.verify(bytes, wrong),
            Err(crate::offline_compact::VerificationError::Verify(Error::TransferInvariant { details }))
                if details == "execution effect independent statement expectation mismatch"));
    }
}

/// Every decoded child contributes exactly its leaves and parent hashes.
fn assert_captured_child_work(
    captured: &CapturedArtifact<'_>,
    verified: &crate::offline_compact::VerifiedArtifact,
) {
    let (bytes, frame, wire) = (&captured.bytes, &captured.frame, &captured.wire);
    assert_eq!(verified.work().row_leaves, 2 * QUERY_COUNT);
    assert_eq!(verified.work().oracle_leaves, 2 * QUERY_COUNT);
    assert!(frame.len() <= 1024 * 1024);
    assert!(bytes.len() <= 1024 * 1024);
    let mut observed_roots = Vec::new();
    let mut fri_leaves = 0;
    let mut parent_hashes = 0;
    for child in &wire.segments {
        assert!(child.len() <= 512 * 1024);
        let proof = crate::backend::deep_proof::decode_with_allocation(
            child,
            512 * 1024,
            policy().max_segment_decode_allocation_charges,
        )
        .unwrap();
        observed_roots.push(proof.row_root);
        fri_leaves += proof
            .rounds
            .iter()
            .map(|round| round.groups.len())
            .sum::<usize>()
            + 1;
        // Each binary multiproof reconstructs leaves + frontier - 1 parents;
        // the sole terminal leaf has one required duplicate-child parent.
        parent_hashes += proof.rows.len() + proof.row_siblings.len() - 1
            + proof.quotients.len()
            + proof.quotient_siblings.len()
            - 1
            + proof
                .rounds
                .iter()
                .map(|round| round.groups.len() + round.siblings.len() - 1)
                .sum::<usize>()
            + 1;
    }
    assert_eq!(observed_roots, verified.air_row_roots());
    assert_eq!(verified.work().fri_leaves, fri_leaves);
    assert_eq!(verified.work().parent_hashes, parent_hashes);
    assert_ne!(
        wire.intermediate_roots[0],
        captured.expected.inputs.old_root
    );
    assert_ne!(
        wire.intermediate_roots[0],
        captured.expected.inputs.new_root
    );
    captured.valid_context(&wire.intermediate_roots);
}

/// Inclusive cumulative outer/child charges and elements remain in force
/// even inside a stricter caller scope. No child can reset that scope.
fn assert_captured_decode_scopes(
    captured: &CapturedArtifact<'_>,
    verified: &crate::offline_compact::VerifiedArtifact,
) {
    let bytes = &captured.bytes;
    let (measured, usage) =
        norito::core::with_decode_limits_measured(policy().total_decode, || {
            captured.verify_limits(bytes, &policy())
        });
    assert_eq!(&measured.unwrap(), verified);
    assert!(usage.total_allocated_bytes() > captured.frame.len());
    let mut exact = policy();
    exact.total_decode = DecodeLimits::new(
        20 * 1024 * 1024,
        20 * 1024 * 1024,
        usage.total_elements(),
        usage.total_allocated_bytes(),
        32,
    );
    assert_eq!(&captured.verify_limits(bytes, &exact).unwrap(), verified);
    for (elements, allocation) in [
        (usage.total_elements() - 1, usage.total_allocated_bytes()),
        (usage.total_elements(), usage.total_allocated_bytes() - 1),
    ] {
        let mut low = exact;
        low.total_decode =
            DecodeLimits::new(20 * 1024 * 1024, 20 * 1024 * 1024, elements, allocation, 32);
        assert!(captured.verify_limits(bytes, &low).is_err());
        assert!(
            norito::core::with_decode_limits_scope(low.total_decode, || captured
                .verify_limits(bytes, &policy()))
            .is_err()
        );
    }
}

/// The internal raw-bundle verifier agrees with the public artifact summary.
fn assert_captured_raw_bundle(
    captured: &CapturedArtifact<'_>,
    verified: &crate::offline_compact::VerifiedArtifact,
) {
    let (is_axt, expected, context) = (captured.is_axt, captured.expected, captured.context);
    let (bytes, frame) = (&captured.bytes, &captured.frame);
    let (raw_result, bundle_usage) = if is_axt {
        with_prepared_quantity_statement(
            captured.statement,
            &expected.internal(),
            ProofSemantics::AxtTransferClaim,
            policy().public_statement,
            |prepared| {
                Ok(norito::core::with_decode_limits_measured(
                    policy().total_decode,
                    || {
                        compact_bundle::verify_axt_transfer_bundle_with_allocation(
                            prepared,
                            &expected.internal(),
                            context.internal(),
                            frame,
                            policy().bundle.internal(),
                            policy().max_segment_decode_allocation_charges,
                        )
                    },
                ))
            },
        )
        .unwrap()
    } else {
        with_effect_credit(captured.effect, |budget, credit| {
            let limits = effect_support::fixture::limits(policy());
            norito::core::with_decode_limits_measured(policy().total_decode, || {
                effect_bundle::verify(
                    &EffectVerificationInputs {
                        statement: &SourceExecutionEffectStatement::from_owned(
                            &captured.effect.statement,
                        ),
                        source: &captured.effect.source,
                        expected: captured.effect.facts(),
                    },
                    frame,
                    EffectVerificationLimits {
                        public: limits.public_policy(),
                        bundle: limits.bundle.internal(),
                        max_segment_decode_allocation_charges: limits
                            .max_segment_decode_allocation_charges,
                    },
                    budget,
                    credit,
                )
            })
        })
    };
    let raw_result = raw_result.unwrap();
    assert_internal_artifact_matches_public(
        bytes,
        is_axt,
        expected,
        context,
        captured.effect,
        verified,
        &raw_result,
    );
    assert_eq!(raw_result.public_io(), expected.internal());
    assert_eq!(raw_result.row_roots(), verified.air_row_roots());
    assert_eq!(raw_result.statement_bytes(), verified.statement_bytes());
    assert_eq!(raw_result.wire_bytes(), verified.bundle_frame_bytes());
    let raw_work = raw_result.work();
    assert_eq!(
        verified.work(),
        crate::offline_compact::VerificationWork {
            proof_bytes: raw_work.proof_bytes,
            transcripts: raw_work.transcripts,
            row_leaves: raw_work.row_leaves,
            oracle_leaves: raw_work.oracle_leaves,
            fri_leaves: raw_work.fri_leaves,
            parent_hashes: raw_work.parent_hashes,
            air_evaluations: raw_work.air_evaluations,
            terminal_degree_checks: raw_work.terminal_degree_checks,
        }
    );
    let mut exact_bundle = policy();
    exact_bundle.bundle.max_total_decode_allocation_charges = bundle_usage.total_allocated_bytes();
    assert_eq!(
        &captured.verify_limits(bytes, &exact_bundle).unwrap(),
        verified
    );
    exact_bundle.bundle.max_total_decode_allocation_charges -= 1;
    assert!(captured.verify_limits(bytes, &exact_bundle).is_err());
}

/// Every inclusive bundle policy boundary rejects one unit below the artifact.
fn assert_captured_bundle_boundaries(
    captured: &CapturedArtifact<'_>,
    verified: &crate::offline_compact::VerifiedArtifact,
) {
    let (bytes, frame, wire) = (&captured.bytes, &captured.frame, &captured.wire);
    for boundary in 0..5 {
        let mut low = policy();
        match boundary {
            0 => low.bundle.max_segments = 1,
            1 => low.bundle.max_total_queries = 2 * QUERY_COUNT - 1,
            2 => low.bundle.max_total_statement_bytes = verified.statement_bytes() - 1,
            3 => low.bundle.max_wire_bytes = frame.len() - 1,
            4 => {
                low.bundle.segment.max_proof_bytes =
                    wire.segments.iter().map(Vec::len).max().unwrap() - 1
            }
            _ => unreachable!(),
        }
        assert!(
            captured.verify_limits(bytes, &low).is_err(),
            "inclusive policy boundary {boundary}"
        );
    }
    let mut no_child_allocation = policy();
    no_child_allocation.max_segment_decode_allocation_charges = 0;
    assert!(captured.verify_limits(bytes, &no_child_allocation).is_err());
    let mut one_child = policy();
    one_child.bundle.max_segments = 1;
    assert!(captured.verify_limits(bytes, &one_child).is_err());
}

/// Re-encode valid transports so failures exercise the child/context
/// checks, not a damaged outer checksum. Exact-count errors still reject
/// the complete bundle; no successfully checked prefix is returned.
fn assert_captured_bundle_mutations_rejected(captured: &CapturedArtifact<'_>) {
    let (is_axt, expected) = (captured.is_axt, captured.expected);
    let (bytes, frame, wire) = (&captured.bytes, &captured.frame, &captured.wire);
    for mutation in 0..7 {
        let mut changed = wire.clone();
        match mutation {
            0 => changed.segments.swap(0, 1),
            1 => changed.segments[1] = changed.segments[0].clone(),
            2 => {
                changed.segments.pop();
            }
            // A short extra carrier keeps this malformed count within the
            // enclosing byte cap; count rejection precedes child decoding.
            3 => changed.segments.push(vec![0]),
            4 => changed.intermediate_roots[0][0] ^= 1,
            5 => {
                let last = changed.segments[1].len() - 1;
                changed.segments[1][last] ^= 1;
            }
            6 => {
                assert!(changed.segments[0].pop().is_some());
            }
            _ => unreachable!(),
        }
        if mutation == 4 {
            captured.valid_context(&changed.intermediate_roots);
        }
        let changed = captured.wrap(raw_bundle_frame(&changed, is_axt));
        let error = captured.verify(&changed, expected).unwrap_err();
        if matches!(mutation, 0 | 1 | 4) {
            assert_deep_context_rejected(&error);
        } else if matches!(mutation, 2 | 3) {
            assert!(matches!(
                error,
                crate::offline_compact::VerificationError::Verify(Error::InvalidTraceShape { details })
                    if details == "compact bundle segment/root count mismatch"
            ));
        } else if mutation == 6 {
            assert!(matches!(
                error,
                crate::offline_compact::VerificationError::Verify(Error::Encode(_))
            ));
        }
    }
    let mut corrupted_artifact = bytes.clone();
    *corrupted_artifact.last_mut().unwrap() ^= 1;
    assert!(captured.verify(&corrupted_artifact, expected).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(captured.verify(&trailing, expected).is_err());
    let mut trailing_bundle = frame.clone();
    trailing_bundle.push(0);
    let trailing = captured.wrap(trailing_bundle);
    assert!(captured.verify(&trailing, expected).is_err());
}

/// Change both the advertisement and independent expectation together:
/// these remain valid public statements and must fail proof binding.
fn assert_captured_changed_statements_rejected(captured: &CapturedArtifact<'_>) {
    for change_authority in [false, true] {
        if captured.is_axt {
            let mut changed_statement = captured.statement.clone();
            if change_authority {
                changed_statement.transcripts[1].authority_digest =
                    Hash::new(b"different second occurrence authority");
            } else {
                changed_statement.public_inputs.perm_root[0] ^= 1;
            }
            let changed_expected = self::expected(&changed_statement);
            assert_valid_public_context(
                &changed_statement,
                changed_expected,
                captured.context,
                &captured.wire.intermediate_roots,
            );
            let changed = Artifact::new(&changed_statement, captured.context)
                .finish(captured.frame.clone(), &policy())
                .unwrap();
            assert_deep_context_rejected(&captured.verify(&changed, changed_expected).unwrap_err());
        } else {
            let mut changed = captured.effect.clone();
            if change_authority {
                changed.statement.effects.effects[1].authority_digest =
                    Hash::new(b"different second occurrence authority");
                changed.source.effects_digest =
                    iroha_data_model::fastpq::execution_effects_digest_v1(
                        &changed.statement.effects,
                    )
                    .unwrap()
                    .into();
            } else {
                changed.statement.public_inputs.perm_root[0] ^= 1;
                changed.source.perm_root = changed.statement.public_inputs.perm_root;
            }
            assert_valid_effect_context(&changed, &captured.wire.intermediate_roots);
            let bytes = execution_effect::encode_artifact(
                &SourceExecutionEffectStatement::from_owned(&changed.statement),
                &changed.source,
                &captured.frame,
                &effect_support::fixture::limits(policy()),
            )
            .unwrap();
            // Independently recomputed complete source/effect/statement expectations
            // agree. Only the authentic original child context now differs.
            assert_deep_context_rejected(&changed.verify(&bytes, policy()).unwrap_err());
        }
    }
}

/// Changed AXT metadata, remote claims or mirrors reject the unchanged proof.
fn assert_captured_axt_contexts_rejected(
    captured: &CapturedArtifact<'_>,
    metadata: &FastpqAxtPublicMetadataV1,
    mirrors: FastpqAxtPreProofMirrorsV1,
) {
    use iroha_data_model::nexus::compute_remote_spend_claim_commitment_v1;
    let (statement, expected, context) = (captured.statement, captured.expected, captured.context);
    let remote = context.remote_spend_claims.unwrap();
    assert_eq!(remote.len(), 2);
    assert_ne!(remote[0].handle_replay_key, remote[1].handle_replay_key);
    assert_eq!(remote[0].effective_amount, remote[1].effective_amount);
    assert_eq!(remote[0].from, remote[1].from);
    assert_eq!(remote[0].to, remote[1].to);
    let mut changed_metadata = metadata.clone();
    changed_metadata.manifest_root[0] ^= 1;
    let changed_metadata_context = ExpectedAxtContext {
        metadata: &changed_metadata,
        mirrors: FastpqAxtPreProofMirrorsV1 {
            manifest_root: changed_metadata.manifest_root,
            ..mirrors
        },
        ..context
    };
    let mut changed_remote = remote.to_vec();
    changed_remote[0].handle_replay_key.handle_era = 17;
    changed_remote.sort_by_key(compute_remote_spend_claim_commitment_v1);
    let mut changed_binding = (*context.binding).clone();
    changed_binding.remote_spend_intent_commitments = changed_remote
        .iter()
        .map(compute_remote_spend_claim_commitment_v1)
        .collect();
    let changed_remote_context = ExpectedAxtContext {
        binding: &changed_binding,
        remote_spend_claims: Some(&changed_remote),
        ..context
    };
    for changed_context in [changed_metadata_context, changed_remote_context] {
        assert_valid_public_context(
            statement,
            expected,
            changed_context,
            &captured.wire.intermediate_roots,
        );
        let changed = Artifact::new(statement, changed_context)
            .finish(captured.frame.clone(), &policy())
            .unwrap();
        assert_deep_context_rejected(
            &verify_quantity_axt_artifact(&changed, expected, changed_context, policy())
                .unwrap_err(),
        );
    }
    let mut omitted_remote = remote.to_vec();
    omitted_remote.pop();
    let mut omitted_binding = (*context.binding).clone();
    omitted_binding.remote_spend_intent_commitments = omitted_remote
        .iter()
        .map(compute_remote_spend_claim_commitment_v1)
        .collect();
    let omitted = ExpectedAxtContext {
        binding: &omitted_binding,
        remote_spend_claims: Some(&omitted_remote),
        ..context
    };
    let changed = Artifact::new(statement, omitted)
        .finish(captured.frame.clone(), &policy())
        .unwrap();
    assert!(
        matches!(verify_quantity_axt_artifact(&changed, expected, omitted, policy()),
        Err(crate::offline_compact::VerificationError::Verify(Error::InvalidAxtBinding { details }))
        if details.contains("one-for-one"))
    );
    let missing = ExpectedAxtContext {
        remote_spend_claims: None,
        ..context
    };
    let changed = Artifact::new(statement, missing)
        .finish(captured.frame.clone(), &policy())
        .unwrap();
    assert!(matches!(
        verify_quantity_axt_artifact(&changed, expected, missing, policy()),
        Err(crate::offline_compact::VerificationError::Verify(
            Error::MissingMetadata { .. }
        ))
    ));
    let mut wrong_mirrors = mirrors;
    wrong_mirrors.manifest_root[0] ^= 1;
    let wrong = ExpectedAxtContext {
        mirrors: wrong_mirrors,
        ..context
    };
    let changed = Artifact::new(statement, wrong)
        .finish(captured.frame.clone(), &policy())
        .unwrap();
    assert!(matches!(
        verify_quantity_axt_artifact(&changed, expected, wrong, policy()),
        Err(crate::offline_compact::VerificationError::Verify(
            Error::InvalidAxtBinding { .. }
        ))
    ));
}

/// Retag both enclosing transports while leaving authenticated children
/// intact: the distinct ordinary/AXT relation identity still rejects.
fn assert_captured_retag_rejected(captured: &CapturedArtifact<'_>) {
    let (statement, context) = (captured.statement, captured.context);
    let opposite = !captured.is_axt;
    let expected = if opposite {
        self::expected(statement)
    } else {
        captured.effect.public_expectation()
    };
    if opposite {
        assert_valid_public_context(
            statement,
            expected,
            context,
            &captured.wire.intermediate_roots,
        );
    } else {
        assert_valid_effect_context(captured.effect, &captured.wire.intermediate_roots);
    }
    let retagged = TestArtifact::new(statement, captured.effect, opposite.then_some(context))
        .finish(raw_bundle_frame(&captured.wire, opposite), &policy())
        .unwrap();
    let error = if opposite {
        verify_quantity_axt_artifact(&retagged, expected, context, policy())
    } else {
        captured.effect.verify(&retagged, policy())
    }
    .unwrap_err();
    assert_deep_context_rejected(&error);
    if captured.is_axt {
        assert!(captured.effect.verify(&captured.bytes, policy()).is_err());
    } else {
        assert!(
            verify_quantity_axt_artifact(&captured.bytes, expected, context, policy()).is_err()
        );
    }
}

#[test]
#[ignore = "read-only complete artifacts supplied by FASTPQ_TEST_ORDINARY_ARTIFACT and FASTPQ_TEST_AXT_ARTIFACT"]
fn captured_public_producer_artifacts_verify_against_independent_fixture() {
    // The paths are test-only inputs. Expectations come from the same independent
    // fixture as the producer regression, never from the supplied artifact bytes.
    let f = fixture();
    let statement = f.model();
    let expected = expected(&statement);
    let (metadata, mirrors) = axt_fields(&f);
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let effect = EffectFixture::from_transfer_facts(&statement);
    for (is_axt, variable) in [
        (false, "FASTPQ_TEST_ORDINARY_ARTIFACT"),
        (true, "FASTPQ_TEST_AXT_ARTIFACT"),
    ] {
        let profile = if is_axt {
            crate::offline_compact::quantity_profile_id()
        } else {
            execution_effect_profile_id()
        };
        let expected = if is_axt {
            expected
        } else {
            effect.public_expectation()
        };
        let bytes = read_public_artifact(variable, if is_axt { "axt" } else { "ordinary" });
        let verify = |bytes: &[u8], expected| {
            if is_axt {
                verify_quantity_axt_artifact(bytes, expected, context, policy())
            } else {
                verify_effect_public(&effect, bytes, expected, &policy())
            }
        };
        let started = std::time::Instant::now();
        let verified = {
            let flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            let verified = verify(&bytes, expected).unwrap();
            assert_eq!(norito::core::get_decode_flags(), flags);
            verified
        };
        let elapsed = started.elapsed();
        let (frame, wire) = decode_captured_bundle(&bytes, is_axt, &statement, &effect, profile);
        let captured = CapturedArtifact {
            is_axt,
            statement: &statement,
            effect: &effect,
            expected,
            context,
            bytes,
            frame,
            wire,
        };
        assert_captured_identity(&captured, &verified, profile);
        // Preserve the complete raw-bundle acceptance, ordering, root-chain,
        // context and resource assertions through the normal public entry point.
        assert_captured_child_work(&captured, &verified);
        assert_captured_decode_scopes(&captured, &verified);
        assert_captured_raw_bundle(&captured, &verified);
        assert_captured_bundle_boundaries(&captured, &verified);
        assert_captured_bundle_mutations_rejected(&captured);
        assert_captured_changed_statements_rejected(&captured);
        if is_axt {
            assert_captured_axt_contexts_rejected(&captured, &metadata, mirrors);
        }
        assert_captured_retag_rejected(&captured);

        eprintln!(
            "captured_quantity_artifact={variable}; bytes={}; sha256={:x}; bundle_frame_bytes={}; segment_bytes={:?}; independent_verification={elapsed:?}; work={:?}",
            captured.bytes.len(),
            Sha256::digest(&captured.bytes),
            captured.frame.len(),
            captured
                .wire
                .segments
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            verified.work()
        );
    }
}

#[test]
fn original_tree_pool_identity_precedes_producer_admission_and_preparation() {
    let f = fixture();
    let statement = f.model();
    let expected = expected(&statement);
    let effect = EffectFixture::from_transfer_facts(&statement);
    let (metadata, mirrors) = axt_fields(&f);
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let (budget, reservation) = funding(statement.transitions.len());
    let equal_limit_foreign = AllocationBudget::new(budget.limit_bytes());
    let mut foreign = equal_limit_foreign
        .try_reserve_bytes(budget.limit_bytes())
        .unwrap();
    let before = foreign.remaining_bytes();
    // Foreign identity wins even when normal production is currently busy.
    let _permit = PRODUCER.lock().unwrap();
    assert!(matches!(
        crate::offline_compact::prove_quantity_ordinary_artifact(
            &SourceExecutionEffectStatement::from_owned(&effect.statement),
            effect.expected(),
            proving(),
            &effect_support::fixture::limits(policy()),
            &budget,
            &mut foreign,
        ),
        Err(ProvingError::Prove(Error::AllocationForeignPool))
    ));
    assert!(matches!(
        crate::offline_compact::prove_quantity_axt_artifact(
            &statement,
            expected,
            context,
            proving(),
            policy(),
            &budget,
            &mut foreign,
        ),
        Err(ProvingError::Prove(Error::AllocationForeignPool))
    ));
    let invalid_batch = crate::TransitionBatch::new("invalid before preparation", f.inputs);
    assert!(matches!(
        crate::prove_axt_bound_batch(&invalid_batch, &f.axt.binding, &budget, &mut foreign,),
        Err(Error::AllocationForeignPool)
    ));
    assert_eq!(foreign.remaining_bytes(), before);
    assert_eq!(equal_limit_foreign.reserved_bytes(), before);
    assert_eq!(reservation.remaining_bytes(), budget.limit_bytes());
    drop(foreign);
    drop(reservation);
    assert_eq!(equal_limit_foreign.reserved_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_prepared_tree_demand_refuses_short_reservations_without_consuming_credit() {
    let f = fixture();
    let statement = f.model();
    let expected = expected(&statement);
    let (metadata, mirrors) = axt_fields(&f);
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let prepared = f.prepare(ProofSemantics::AxtTransferClaim);
    let demand = proving()
        .private_smt
        .allocation_bytes(prepared.transitions().len(), prepared.keys().len())
        .unwrap();
    for available in [0, demand - 1] {
        let budget = AllocationBudget::new(demand);
        let mut reservation = budget.try_reserve_bytes(available).unwrap();
        assert!(matches!(prepare_and_prove(
            &prepared, &statement, expected, context, proving(), policy(), &budget, &mut reservation,
        ), Err(Error::AllocationReservation(iroha_allocation::InsufficientReservation {
            requested_bytes, remaining_bytes,
        })) if requested_bytes == demand && remaining_bytes == available));
        assert_eq!(reservation.remaining_bytes(), available);
        assert_eq!(budget.reserved_bytes(), available);
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_pool_refunds_tree_backing_after_late_root_refusal() {
    let mut f = fixture();
    f.inputs.new_root[0] ^= 1;
    let statement = f.model();
    let expected = expected(&statement);
    let (metadata, mirrors) = axt_fields(&f);
    let context = ExpectedAxtContext {
        binding: &f.axt.binding,
        metadata: &metadata,
        mirrors,
        remote_spend_claims: f.axt.remote.as_deref(),
    };
    let prepared = f.prepare(ProofSemantics::AxtTransferClaim);
    let demand = proving()
        .private_smt
        .allocation_bytes(prepared.transitions().len(), prepared.keys().len())
        .unwrap();
    let budget = AllocationBudget::new(demand);
    for _ in 0..2 {
        let mut reservation = budget.try_reserve_bytes(demand).unwrap();
        assert!(matches!(prepare_and_prove(
            &prepared, &statement, expected, context, proving(), policy(), &budget, &mut reservation,
        ), Err(Error::TransferInvariant { details }) if details.contains("root")));
        assert_eq!(reservation.remaining_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn complete_effect_statement_caps_and_original_headers_use_actual_preflight() {
    let effect = EffectFixture::from_transfer_facts(&fixture().model());
    let view = SourceExecutionEffectStatement::from_owned(&effect.statement);
    let mut limits = effect_support::fixture::limits(policy());
    limits.public_statement.max_effects = 2;
    limits.public_statement.max_rows = 4;
    limits.public_statement.max_public_bytes = norito::canonical_frame_len(&view).unwrap();
    assert_eq!(
        execution_effect::preflight_for_test(&view, effect.expected(), proving(), &limits).unwrap(),
        2
    );
    for (field, actual, name) in [
        (0, 2, "max_execution_effects"),
        (1, 4, "max_execution_effect_rows"),
        (
            2,
            limits.public_statement.max_public_bytes,
            "max_compact_producer_statement_bytes",
        ),
    ] {
        let mut short = limits;
        match field {
            0 => short.public_statement.max_effects = actual - 1,
            1 => short.public_statement.max_rows = actual - 1,
            _ => short.public_statement.max_public_bytes = actual - 1,
        }
        assert_limit(
            &execution_effect::preflight_for_test(&view, effect.expected(), proving(), &short),
            name,
            actual,
            actual - 1,
        );
    }
    for authority in [true, false] {
        let mut changed = effect.statement.clone();
        if authority {
            changed.effects.effects[0].authority_digest =
                Hash::new(b"different original authority");
        } else {
            changed.effects.context.entry.entry_hash = Hash::new(b"different original batch");
        }
        assert!(matches!(
            execution_effect::preflight_for_test(
                &SourceExecutionEffectStatement::from_owned(&changed),
                effect.expected(),
                proving(),
                &limits
            ),
            Err(Error::PublicIoMismatch {
                field: "compact_public_statement_digest"
            })
        ));
    }
    let mut empty = effect.statement.clone();
    empty.effects.effects.clear();
    assert!(matches!(
        execution_effect::preflight_for_test(
            &SourceExecutionEffectStatement::from_owned(&empty),
            effect.expected(),
            proving(),
            &limits
        ),
        Err(Error::TransferInvariant { .. })
    ));
}

#[test]
fn complete_effect_contexts_and_private_paths_preflight_before_physical_columns() {
    let effect = EffectFixture::from_transfer_facts(&fixture().model());
    with_effect_credit(&effect, |budget, credit| {
        let view = SourceExecutionEffectStatement::from_owned(&effect.statement);
        let limits = effect_support::fixture::limits(policy());
        let prepared = prepare_source_execution_effect_view(
            &view,
            &effect.source,
            effect.facts(),
            limits.public_policy(),
            budget,
            credit,
        )
        .unwrap();
        let private = prepared
            .build_smt_witnesses(proving().private_smt, budget, credit)
            .unwrap();
        let roots = [private.pairs()[0][1].root_after];
        drop(prepared);
        let batch = ExecutionEffectBatch::new(
            &view,
            &effect.source,
            effect.facts(),
            &roots,
            EffectBatchLimits {
                public: limits.public_policy(),
                context: BatchContextLimits {
                    max_segments: 2,
                    max_total_statement_bytes: policy().bundle.max_total_statement_bytes,
                },
            },
            budget,
            credit,
        )
        .unwrap();
        let mut bad_private = private.pairs().to_vec();
        bad_private[0][0].path_bits[0] ^= 1;
        let calls = Cell::new(0);
        let result = segments(
            batch.statements(),
            &bad_private,
            |ordinal| {
                calls.set(calls.get() + 1);
                if ordinal == 1 {
                    return Err(invalid("second segment rejected before any witness"));
                }
                batch.segment(ordinal)
            },
            proving(),
            policy(),
        );
        assert!(matches!(result, Err(Error::TransferInvariant { details })
            if details == "second segment rejected before any witness"));
        assert_eq!(calls.get(), 2);
        calls.set(0);
        let result = segments(
            batch.statements(),
            &bad_private[..1],
            |ordinal| {
                calls.set(calls.get() + 1);
                batch.segment(ordinal)
            },
            proving(),
            policy(),
        );
        assert!(matches!(result, Err(Error::TransferInvariant { details })
            if details.contains("pair count differs")));
        assert_eq!(calls.get(), 0);
        for wrong_path in [true, false] {
            let mut pair = private.pairs()[0].clone();
            if wrong_path {
                pair[0].path_bits[0] ^= 1;
            } else {
                pair[1].siblings.pop();
            }
            assert!(matches!(columns(&batch.statements()[0], &pair),
                Err(Error::TransferInvariant { details }) if details.contains("private path differs")));
        }
    });
}
