//! Whole-profile allocation bounds and opt-in native resource diagnostics.

use super::*;

#[test]
fn small_native_source_forecast_uses_full_widths_and_rejects_oversized_extents() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let shape = main_resources::MainSmallSourceShapeV1 {
        der_active_rows: ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        io_active_rows: 1 << 18,
        io_declarations_payload: 4096,
        projection_rows: 1 << 15,
    };
    let (retained, scratch) = shape.allocation_forecast_v1(&layout).unwrap();
    let matrices = 327_680 * (76 + 196) * 8 + (1 << 18) * (28 + 17 + 39) * 8 + (1 << 15) * 32 * 8;
    assert_eq!(matrices, 897_581_056);
    assert!(retained >= matrices + 4096);
    assert!(scratch < main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1);
    let mut changed = shape;
    changed.der_active_rows += 1;
    assert!(changed.allocation_forecast_v1(&layout).is_err());
    changed = shape;
    changed.io_active_rows += 1;
    assert!(changed.allocation_forecast_v1(&layout).is_err());
    changed = shape;
    changed.projection_rows -= 1;
    assert!(changed.allocation_forecast_v1(&layout).is_err());
    changed = shape;
    changed.io_declarations_payload = usize::MAX;
    assert!(changed.allocation_forecast_v1(&layout).is_err());
    changed = shape;
    changed.io_active_rows = 1;
    assert_eq!(
        changed.allocation_forecast_v1(&layout).unwrap(),
        (retained, scratch)
    );
}

#[test]
fn canonical_source_shape_forecasts_fit_the_preconstruction_allowances() {
    use super::super::super::sha_call_bus_stark::ZkX509ShaCallPublicShapeV1;
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let (small, small_scratch) = main_resources::MainSmallSourceShapeV1 {
        der_active_rows: ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        io_active_rows: 1 << 18,
        io_declarations_payload: 1 << 20,
        projection_rows: 1 << 15,
    }
    .allocation_forecast_v1(&layout)
    .unwrap();
    let sha_shape = ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 4,
    };
    let p256 = P256MainBaseSourceV1::allocation_forecast_v1().unwrap();
    let p256_scratch = P256MainBaseSourceV1::replay_scratch_forecast_v1().unwrap();
    let sha_fixed = ZkX509ShaBatchFixedProviderV1::allocation_forecast_v1(sha_shape).unwrap();
    let sha_scratch = ZkX509ShaBatchFixedProviderV1::replay_scratch_forecast_v1(sha_shape).unwrap();
    let rfc_coefficients = main_retained_rfc::MainRetainedRfcV1::forecast_all_v1(&layout).unwrap();
    let sha_aux = ZkX509ShaBatchSegmentAuxSourceV1::native_aux_cache_forecast_all_v1().unwrap();
    assert!(sha_aux > 1_308_622_848); // Four full 524288 x 78 field matrices plus terminals.
    let retained = small + p256 + sha_fixed + rfc_coefficients + sha_aux;
    assert!(retained <= main_resources::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1);
    let serial_scratch = small_scratch.max(sha_scratch).max(p256_scratch);
    assert!(serial_scratch <= main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1);
    eprintln!(
        "MAIN source shape forecasts: retained={retained}, small={small}, p256={p256}, sha_fixed={sha_fixed}, sha_aux={sha_aux}, retained_rfc={rfc_coefficients}, serial_scratch={serial_scratch}"
    );
    // These construction bounds do not materialize or qualify the separately
    // borrowed maximum-profile assembly, nor measure allocator/process RSS.
}

#[test]
fn source_payload_admission_includes_scratch_reserve_and_capacity_overflow() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let reserve = main_resources::MAIN_PROVER_RUNTIME_RESERVE_BYTES_V1;
    let scratch = 13_579;
    let powers = main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1;
    assert_eq!(powers, 4_194_384);
    let available = plan.remaining_source_and_runtime_envelope - reserve - scratch - powers;
    let first = available / 3;
    let second = available - first;
    assert_eq!(
        plan.check_source_payloads_v1(&[first, second], scratch)
            .unwrap() as u64,
        super::super::super::profile::ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1
    );
    assert!(matches!(
        plan.check_source_payloads_v1(&[first, second + 1], scratch),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    assert!(matches!(
        plan.check_source_payloads_v1(&[first, second], scratch + 1),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    assert!(plan.check_source_payloads_v1(&[usize::MAX, 1], 0).is_err());
    assert!(plan.check_source_payloads_v1(&[0], usize::MAX).is_err());
    assert_eq!(
        plan.check_source_payloads_v1(&[], 0).unwrap(),
        plan.maximum_live_buffers + reserve + powers
    );
}

#[test]
fn native_source_budget_is_reserved_before_construction_and_rechecked_after_binding() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let source_limit = main_resources::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1;
    let scratch = main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1;
    let reserve = main_resources::MAIN_PROVER_RUNTIME_RESERVE_BYTES_V1;
    let assembly_limit = plan.remaining_source_and_runtime_envelope
        - source_limit
        - scratch
        - reserve
        - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1;
    assert_eq!(
        plan.check_before_sources_v1(assembly_limit).unwrap() as u64,
        super::super::super::profile::ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1
    );
    assert!(matches!(
        plan.check_before_sources_v1(assembly_limit + 1),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    assert_eq!(
        plan.check_native_sources_v1(assembly_limit, &[source_limit / 2, source_limit / 2])
            .unwrap(),
        plan.check_before_sources_v1(assembly_limit).unwrap()
    );
    assert!(matches!(
        plan.check_native_sources_v1(0, &[source_limit, 1]),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    assert!(plan.check_native_sources_v1(0, &[usize::MAX, 1]).is_err());
    let sha_aux = ZkX509ShaBatchSegmentAuxSourceV1::native_aux_cache_forecast_all_v1().unwrap();
    assert_eq!(
        plan.check_native_sources_v1(assembly_limit, &[source_limit - sha_aux, sha_aux])
            .unwrap(),
        plan.check_before_sources_v1(assembly_limit).unwrap()
    );
    assert!(matches!(
        plan.check_native_sources_v1(0, &[source_limit - sha_aux + 1, sha_aux]),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
    // The source transition reuses the same retained assembly charge, rather
    // than treating a borrowed assembly as already freed after base commitment.
    assert!(matches!(
        plan.check_native_sources_v1(assembly_limit + 1, &[source_limit]),
        Err(ZkX509StarkErrorV1::ProofTooLarge)
    ));
}

#[test]
fn replay_buffer_plan_charges_live_owners_and_leaves_an_explicit_source_envelope() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    eprintln!("MAIN current owner plan before original pins: {plan:?}");
    assert_eq!(plan.masks, 84_422_208);
    let cut_payload = aggregate::retained_commitment::RetainedMerkleCutV1::payload_bound_v1(
        layout.common_lde_size(),
    )
    .unwrap();
    assert_eq!(
        core::mem::size_of::<aggregate::retained_commitment::RetainedMerkleCutV1>(),
        80
    );
    assert_eq!(cut_payload, 12_582_912 + 80);
    assert_eq!(plan.retained_cuts, 2 * cut_payload);
    assert_eq!(plan.retained_cuts, 25_165_984);
    let total_width = layout
        .trace_groups
        .iter()
        .map(|group| group.base_width + group.aux_width)
        .sum::<usize>();
    assert_eq!(
        plan.selected_replay,
        aggregate::retained_commitment::selected_payload_bound_v1(
            layout.common_lde_size(),
            total_width,
            AGGREGATE_PARAMETERS_V1.query_count,
        )
        .unwrap()
    );
    assert!(plan.selected_replay < plan.joined_streams);
    for stage in [
        plan.masks + plan.retained_cuts + plan.joined_streams + plan.replay_batch,
        plan.masks + plan.retained_cuts + plan.quotient_stage + plan.replay_batch,
        plan.masks
            + plan.retained_cuts
            + plan.selected_replay
            + plan.replay_batch
            + plan.composition
            + plan.fri_stage
            + plan.openings,
    ] {
        assert!(stage <= plan.maximum_live_buffers);
    }
    let mut overflowing = plan;
    overflowing.retained_cuts = usize::MAX;
    for registration in &layout.registered_segments {
        assert!(
            overflowing
                .quotient_cache_plan_v1(&layout, *registration)
                .is_err()
        );
    }
    assert_eq!(
        plan.joined_streams,
        layout.common_lde_size()
            * core::mem::size_of::<
                crate::privacy_engines::privacy_outer_hash::PrivacyOuterLastFieldStreamV1,
            >()
    );
    assert_eq!(
        plan.maximum_live_buffers,
        plan.masks
            + (plan.quotient_stage + plan.replay_batch).max(
                plan.joined_streams
                    + plan.replay_batch
                    + plan.composition
                    + plan.fri_stage
                    + plan.openings
            )
    );
    assert_eq!(
        (plan.maximum_live_buffers + plan.remaining_source_and_runtime_envelope) as u64,
        super::super::super::profile::ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1
    );
    // The current RFC stripe is the largest registration phase. It retains
    // the full 147-column fixed stripe, all quotient originals and the outer
    // chunks; interpolation and incoming chunks are charged in their own phase.
    // The unchanged FRI envelope still dominates the global arithmetic bound.
    assert_eq!(core::mem::size_of::<E>(), 32);
    assert_eq!(
        super::super::super::composition_masking::QuotientChunkGeometryV1::mask_scratch_bytes_v1(),
        core::mem::size_of::<E>()
    );
    assert_eq!(plan.quotient_stage, 3_166_719_416);
    assert_eq!(
        plan.maximum_live_buffers,
        3_697_993_152 + core::mem::size_of::<E>()
    );
    assert_eq!(
        plan.remaining_source_and_runtime_envelope,
        9_186_908_736 - core::mem::size_of::<E>()
    );
    assert_eq!(
        plan.remaining_source_and_runtime_envelope
            - main_resources::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1
            - main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1
            - main_resources::MAIN_PROVER_RUNTIME_RESERVE_BYTES_V1,
        596_974_144 - core::mem::size_of::<E>(),
    );
    assert_eq!(
        plan.remaining_source_and_runtime_envelope
            - main_resources::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1
            - main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1
            - main_resources::MAIN_PROVER_RUNTIME_RESERVE_BYTES_V1
            - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1,
        592_779_760 - core::mem::size_of::<E>()
    );
    // This remainder must also cover borrowed sources and process overhead;
    // passing this buffer check is not whole-prover or RSS qualification.
    eprintln!("MAIN replay transform buffer plan: {plan:?}");
    let mut invalid = layout;
    invalid.trace_groups[5].base_width += 1;
    assert!(main_resources::MainProverBufferPlanV1::new_v1(&invalid).is_err());
}

#[test]
fn whole_main_retaining_every_masked_coefficient_exceeds_the_release_memory_ceiling() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let geometry = layout
        .trace_groups
        .iter()
        .map(|group| (group.native_trace_log2, group.base_width + group.aux_width))
        .collect::<Vec<_>>();
    assert_eq!(
        geometry,
        [
            (5, 800),
            (8, 190),
            (15, 49),
            (16, 805),
            (18, 67),
            (19, 3900)
        ]
    );
    let masks = MASK_DEGREE + 1;
    assert_eq!(masks, 1816);
    let coefficient_bytes = geometry
        .iter()
        .map(|(log, width)| ((1_u64 << log) + masks as u64) * *width as u64 * 8)
        .sum::<u64>();
    let mask_bytes = geometry
        .iter()
        .map(|(_, width)| *width as u64 * masks as u64 * 8)
        .sum::<u64>();
    assert_eq!(coefficient_bytes, 17_018_207_808);
    assert_eq!(mask_bytes, 84_422_208);
    assert!(coefficient_bytes > super::super::super::profile::ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1);
    // This is a payload lower bound, excluding borrowed assembly/source traces,
    // quotient matrices, public fixed polynomials, FFT scratch and allocator overhead.
    assert_eq!(((1_u64 << 19) + masks as u64) * 3900 * 8, 16_414_444_800);
}

/// Admit the actual complete maximum fixture before entropy or commitments.
#[test]
fn maximum_profile_assembly_payload_fits_source_admission_before_masks() {
    use super::super::super::{
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum structural release fixture");
    fixture.resource_shape.validate_v1().unwrap();
    assert_eq!(fixture.witness.certificate_chain_der.len(), 3);
    assert_eq!(fixture.statement.disclosed_attributes.len(), 4);
    assert_eq!(fixture.crl_entry_count, 64);
    assert_eq!(fixture.resource_shape.maximum_serial_bytes, 20);
    let trust_anchor = fixture.authoritative_state.trust_anchor();
    let crl = fixture.authoritative_state.crl_record();
    let assembly = build_zk_x509_main_trace_assembly_v1(
        &fixture.statement,
        ZkX509GovernanceV1 {
            trust_anchor: &trust_anchor,
            certificate_policy: fixture.authoritative_state.certificate_policy(),
            crl: &crl,
        },
        &fixture.witness,
    )
    .expect("complete maximum structural MAIN assembly");
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let payload = assembly.allocated_payload_bytes_v1();
    let allowance = plan.remaining_source_and_runtime_envelope
        - main_resources::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1
        - main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1
        - main_resources::MAIN_PROVER_RUNTIME_RESERVE_BYTES_V1
        - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1;
    eprintln!(
        "maximum complete MAIN assembly payload={payload}, allowance={allowance}; capacity accounting only, no RSS or full-proof qualification"
    );
    assert_eq!(
        allowance,
        596_974_144
            - core::mem::size_of::<E>()
            - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1
    );
    assert!(payload <= allowance);
    plan.check_source_shapes_v1(&layout, &assembly)
        .expect("all native source forecasts admitted before masking");
}

/// Run in a separate optimized process with `/usr/bin/time -l` on macOS.
/// This constructs real maximum-structural-shape private inputs and the complete
/// assembly, but deliberately stops before mask sampling or proof construction.
#[test]
#[ignore = "native maximum-shape MAIN assembly allocation/time diagnostic; run --release"]
fn maximum_profile_assembly_payload_and_source_admission_diagnostic() {
    use super::super::super::{
        allocation_payload::{p256_material_v1, sum_v1, vector_v1},
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        profile::ZK_X509_PROVER_TARGET_SECONDS_V1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };
    use std::time::Instant;

    crate::test_support::require_no_debug_assertions("run this diagnostic with --release");
    let fixture_start = Instant::now();
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum structural release fixture");
    fixture.resource_shape.validate_v1().unwrap();
    assert_eq!(fixture.resource_shape.certificate_chain_depth, 3);
    assert_eq!(fixture.statement.disclosed_attributes.len(), 4);
    assert_eq!(fixture.crl_entry_count, 64);
    assert_eq!(fixture.resource_shape.maximum_serial_bytes, 20);
    eprintln!(
        "X509 assembly diagnostic fixture: seconds={:.6}, shape={:?}",
        fixture_start.elapsed().as_secs_f64(),
        fixture.resource_shape,
    );
    let trust_anchor = fixture.authoritative_state.trust_anchor();
    let crl = fixture.authoritative_state.crl_record();
    let start = Instant::now();
    let assembly = build_zk_x509_main_trace_assembly_v1(
        &fixture.statement,
        ZkX509GovernanceV1 {
            trust_anchor: &trust_anchor,
            certificate_policy: fixture.authoritative_state.certificate_policy(),
            crl: &crl,
        },
        &fixture.witness,
    )
    .expect("complete maximum structural MAIN assembly");
    let construction = start.elapsed();
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let payload = assembly.allocated_payload_bytes_v1();
    let p256_materials = sum_v1(assembly.p256_materials.iter().map(p256_material_v1));
    let der_rows = vector_v1(&assembly.der_base.rows);
    let io_rows = vector_v1(&assembly.io.execution) + vector_v1(&assembly.io.sorted);
    let projection_rows = vector_v1(&assembly.projection_trace.base.rows);
    let remaining_owners = payload
        .checked_sub(p256_materials + der_rows + io_rows + projection_rows)
        .expect("component allocation charges are disjoint");
    let assembly_allowance = plan
        .remaining_source_and_runtime_envelope
        .checked_sub(
            main_resources::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1
                + main_resources::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1
                + main_resources::MAIN_PROVER_RUNTIME_RESERVE_BYTES_V1
                + main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1,
        )
        .unwrap();
    let total_columns = layout
        .trace_groups
        .iter()
        .map(|group| group.base_width + group.aux_width)
        .sum::<usize>();
    let common_rows = 1_usize << layout.common_lde_log2;
    let commitment_field_bytes = 2_u64 * total_columns as u64 * common_rows as u64 * 8;
    eprintln!(
        "X509 assembly diagnostic payload: actual={payload}, allowance={assembly_allowance}, p256_materials={p256_materials}, der_rows={der_rows}, io_rows={io_rows}, projection_rows={projection_rows}, other_owned={remaining_owners}, construction_seconds={:.6}, total_prover_target_seconds={ZK_X509_PROVER_TARGET_SECONDS_V1}",
        construction.as_secs_f64(),
    );
    eprintln!(
        "X509 remaining work floor: trace_columns={total_columns}, common_rows={common_rows}, original_plus_opening_commitment_field_bytes={commitment_field_bytes}; excludes source replay, interpolation, quotient stripes, Fp4 constraints/DEEP, FRI, CA, framing and Merkle parents",
    );
    // Print measured data before rejecting the fixture. Do not relax the
    // production allowance merely to turn this diagnostic into a passing test.
    plan.check_source_shapes_v1(&layout, &assembly)
        .expect("maximum structural assembly fits unchanged preconstruction admission");
    let before_drop = Instant::now();
    drop(assembly);
    eprintln!(
        "X509 assembly diagnostic cleanup: seconds={:.6}; payload is not process RSS, construction-only timing is not full-proof qualification",
        before_drop.elapsed().as_secs_f64(),
    );
    assert!(
        construction.as_secs() < ZK_X509_PROVER_TARGET_SECONDS_V1,
        "assembly alone exhausts the unchanged total proving target"
    );
}

/// Synthetic public values isolate the real exact-width streaming hash work.
/// The small single-worker row sample fits caches differently from a full
/// commitment. Its linear extrapolation never qualifies the time limit or
/// measures parallel throughput.
#[test]
#[ignore = "optimized exact-width X509 streaming hash cost diagnostic; run --release"]
fn maximum_profile_streaming_hash_cost_diagnostic() {
    use std::time::Instant;

    crate::test_support::require_no_debug_assertions("run this diagnostic with --release");
    const SAMPLE_ROWS: usize = 128;
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let widths = [
        layout
            .trace_groups
            .iter()
            .map(|group| group.base_width)
            .sum::<usize>(),
        layout
            .trace_groups
            .iter()
            .map(|group| group.aux_width)
            .sum::<usize>(),
    ];
    let full_rows = 1_usize << layout.common_lde_log2;
    let mut expected_roots = None;
    let workers = 1;
    for batch_width in [1, aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] {
        let (roots, seconds) = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                let start = Instant::now();
                let mut roots = Vec::new();
                for (width, (leaf, node)) in widths.into_iter().zip([
                    (
                        AGGREGATE_DOMAINS_V1.base_leaf,
                        AGGREGATE_DOMAINS_V1.base_node,
                    ),
                    (AGGREGATE_DOMAINS_V1.aux_leaf, AGGREGATE_DOMAINS_V1.aux_node),
                ]) {
                    let mut commitment = aggregate::StreamingRowCommitmentV1::new(
                        AGGREGATE_DOMAINS_V1.digest_context,
                        leaf,
                        node,
                        usize::from(u16::MAX),
                        SAMPLE_ROWS,
                        width,
                        &[],
                    )
                    .unwrap();
                    for first in (0..width).step_by(batch_width) {
                        let columns = (first..(first + batch_width).min(width))
                            .map(|column| {
                                (0..SAMPLE_ROWS)
                                    .map(|row| F((row * 31 + column * 17) as u64))
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>();
                        commitment.absorb_columns_v1(&columns).unwrap();
                    }
                    roots.push(commitment.finish().unwrap().commitment.root);
                }
                (roots, start.elapsed().as_secs_f64())
            });
        if let Some(expected) = &expected_roots {
            assert_eq!(&roots, expected);
        } else {
            expected_roots = Some(roots);
        }
        eprintln!(
            "X509 exact-width streaming hash diagnostic: workers={workers}, batch_columns={batch_width}, sample_rows={SAMPLE_ROWS}, base_width={}, aux_width={}, total_width={}, seconds={seconds:.6}, linear_two_full_pass_seconds={:.3}; single-worker diagnostic only, no parallel-throughput claim; excludes FFT/source replay/constraints/FRI/CA, differs in cache residency, concurrent host load must be recorded",
            widths[0],
            widths[1],
            widths.iter().sum::<usize>(),
            seconds * 2.0 * (full_rows / SAMPLE_ROWS) as f64,
        );
    }
}

#[test]
#[ignore = "optimized eight-column native log19/common log22 FFT cost diagnostic; run --release"]
fn maximum_profile_replay_fft_cost_diagnostic() {
    use crate::privacy_engines::transparent_stark::{
        masked_trace_coefficients_on_coset_v1, masked_trace_coefficients_with_mask_v1,
    };
    use rayon::prelude::*;
    use std::time::Instant;

    crate::test_support::require_no_debug_assertions("run this diagnostic with --release");
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let native_log = layout.trace_groups.last().unwrap().native_trace_log2;
    let common_log = layout.common_lde_log2;
    assert_eq!((native_log, common_log), (19, 22));
    let batch_width = aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1;
    let mut coefficients = Vec::with_capacity(batch_width);
    let interpolation_start = Instant::now();
    for column in 0..batch_width {
        let native = ZeroizingMainTraceColumnV1(
            (0..(1_usize << native_log))
                .map(|row| F((row * 31 + column * 17) as u64))
                .collect(),
        );
        let mask = ZeroizingMainTraceColumnV1(
            (0..=MASK_DEGREE)
                .map(|index| F((index * 13 + column * 19 + 1) as u64))
                .collect(),
        );
        coefficients.push(ZeroizingMainTraceColumnV1(
            masked_trace_coefficients_with_mask_v1(&native, native_log, &mask).unwrap(),
        ));
    }
    let interpolation_seconds = interpolation_start.elapsed().as_secs_f64();
    let lde_start = Instant::now();
    let evaluations = coefficients
        .par_iter()
        .map(|column| {
            masked_trace_coefficients_on_coset_v1(column, native_log, common_log)
                .map(ZeroizingMainTraceColumnV1)
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let lde_seconds = lde_start.elapsed().as_secs_f64();
    let rows = 1_usize << common_log;
    let root = goldilocks_primitive_root_v1(common_log).unwrap();
    for (coefficients, evaluations) in coefficients.iter().zip(&evaluations) {
        assert_eq!(evaluations.len(), rows);
        for index in [0, 1, rows - 1] {
            let point = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(index as u128));
            let expected = coefficients
                .iter()
                .rev()
                .fold(F::ZERO, |value, coefficient| {
                    value.mul(point).add(*coefficient)
                });
            assert_eq!(evaluations[index], expected);
        }
    }
    let total_columns = layout
        .trace_groups
        .iter()
        .map(|group| group.base_width + group.aux_width)
        .sum::<usize>();
    let forward_transforms = 2 * total_columns;
    let butterflies = forward_transforms as u64 * (rows / 2) as u64 * u64::from(common_log);
    eprintln!(
        "X509 replay FFT diagnostic: rayon_workers={}, columns={batch_width}, native_rows={}, common_rows={rows}, interpolation_and_mask_seconds={interpolation_seconds:.6}, forward_seconds={lde_seconds:.6}, commitment_forward_transforms={forward_transforms}, commitment_forward_butterflies={butterflies}, linear_commitment_forward_seconds={:.3}; excludes source construction/replay, remaining native IFFTs, constraints/quotient/DEEP, hashing/FRI/CA and host contention",
        rayon::current_num_threads(),
        1_usize << native_log,
        lde_seconds * forward_transforms as f64 / batch_width as f64,
    );
}

#[test]
fn complete_main_work_inventory_includes_quotients_and_all_native_replays() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let buffers = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let mut cached_columns = 0_u64;
    let mut native_cells = 0_u64;
    let mut masked_cells = 0_u64;
    let mut quotient_rows = 0_u64;
    let mut residues = 0_u64;
    let mut quotient_native_iffts = 0_u64;
    let mut quotient_native_butterflies = 0_u64;
    let mut quotient_forward_butterflies = 0_u64;
    let mut quotient_fp4_inverse_butterflies = 0_u64;
    let mut other_native_butterflies = 0_u64;
    let mut fixed_native_butterflies = 0_u64;
    let mut fixed_recovery_iffts = 0_u64;
    let mut fixed_recovery_butterflies = 0_u64;
    let mut columns = 0_u64;
    for registration in &layout.registered_segments {
        let segment = registration.segment;
        let plan = registered_retained_prover_plan_v1(segment, layout.common_lde_log2).unwrap();
        let n = segment.trace_size() as u64;
        let m = plan.quotient_coset_rows as u64;
        let width = (segment.base_width + segment.aux_width) as u64;
        let fixed = segment.fixed_width as u64;
        // The source-bound stripe tests separately pin this public cap.
        let stripe_rows = m.min(1 << 19);
        assert!(n <= stripe_rows);
        let stripes = m / stripe_rows;
        columns += width;
        native_cells += width * n;
        masked_cells += width * (n + MASK_DEGREE as u64 + 1);
        quotient_rows += m;
        residues += m * segment.constraint_count as u64;
        let cache = buffers
            .quotient_cache_plan_v1(&layout, *registration)
            .unwrap();
        let cached = (cache.base_columns + cache.aux_columns) as u64;
        assert!(cache.base_columns <= segment.base_width);
        assert!(cache.aux_columns <= segment.aux_width);
        if segment.adapter == SegmentAdapterIdV1::P256Arithmetic {
            assert!(cache.base_columns == 0 || cache.aux_columns == segment.aux_width);
        } else {
            assert!(cache.aux_columns == 0 || cache.base_columns == segment.base_width);
        }
        if stripes == 1 {
            assert_eq!(cached, 0);
        }
        cached_columns += cached;
        let replays = cached + (width - cached) * stripes;
        quotient_native_iffts += replays;
        quotient_native_butterflies += replays * (n / 2) * u64::from(segment.trace_log2);
        quotient_forward_butterflies += (width + fixed) * (m / 2) * u64::from(stripe_rows.ilog2());
        quotient_fp4_inverse_butterflies += (m / 2) * u64::from(plan.quotient_coset_log2);
        // Initial and opening commitments, DEEP values, and DEEP quotient
        // accumulation each replay every original masked trace polynomial.
        other_native_butterflies += 4 * width * (n / 2) * u64::from(segment.trace_log2);
        fixed_native_butterflies += fixed * (n / 2) * u64::from(segment.trace_log2);
        // Later stripes recover the shifted public coefficients in place.
        // Count these real extra transforms separately from native interpolation.
        fixed_recovery_iffts += fixed * (stripes - 1);
        fixed_recovery_butterflies +=
            fixed * (stripes - 1) * (stripe_rows / 2) * u64::from(stripe_rows.ilog2());
    }
    eprintln!(
        "MAIN current work before original pins: columns={columns}, native_cells={native_cells}, masked_cells={masked_cells}, quotient_rows={quotient_rows}, residues={residues}, cached_columns={cached_columns}, quotient_native_iffts={quotient_native_iffts}, quotient_native_butterflies={quotient_native_butterflies}, quotient_forward_butterflies={quotient_forward_butterflies}, quotient_fp4_inverse_butterflies={quotient_fp4_inverse_butterflies}, other_native_butterflies={other_native_butterflies}, fixed_native_butterflies={fixed_native_butterflies}, fixed_recovery_iffts={fixed_recovery_iffts}, fixed_recovery_butterflies={fixed_recovery_butterflies}"
    );
    assert_eq!(SECURITY_LANES, 1);
    assert_eq!(layout.registered_segments.len(), 49);
    assert_eq!(columns, 5_811);
    assert_eq!(native_cells, 2_116_723_200);
    assert_eq!(masked_cells, 2_127_275_976);
    assert_eq!(quotient_rows, 53_215_232);
    // Per-adapter local residue work from the complete 49-registration census:
    // reduction, low-S, scalar-bit, projection, window, value, byte-memory,
    // strict-DER, RFC5280, SHA-call and P-256 arithmetic, in that order.
    assert_eq!(
        [
            11_796_480_u64,
            770_048,
            2_744_320,
            39_190_528,
            367_001_600,
            2_803_630_080,
            95_420_416,
            3_732_930_560,
            4_498_391_040, // RFC: 2,145 local residues across 2^21 quotient rows.
            9_462_349_824,
            4_771_020_800,
        ]
        .into_iter()
        .sum::<u64>(),
        25_785_245_696
    );
    assert_eq!(residues, 25_785_245_696);
    // The public prefix cache does not enlarge the admitted arithmetic envelope.
    assert_eq!(
        buffers.maximum_live_buffers,
        3_697_993_152 + core::mem::size_of::<E>()
    );
    assert_eq!(
        buffers.remaining_source_and_runtime_envelope,
        9_186_908_736 - core::mem::size_of::<E>()
    );
    // Both cut owners remain live. Phase-specific accounting admits all 283
    // P-256 arithmetic columns in each of five registrations, while the RFC
    // registration retains only its first 26 base columns across four stripes.
    assert_eq!(cached_columns, 3_428);
    assert_eq!(quotient_native_iffts, 7_428);
    assert_eq!(quotient_native_butterflies, 28_071_145_984);
    assert_eq!(quotient_forward_butterflies, 139_336_818_688);
    assert_eq!(quotient_fp4_inverse_butterflies, 561_381_376);
    assert_eq!(other_native_butterflies, 80_069_183_488);
    assert_eq!(fixed_native_butterflies, 8_447_302_080);
    assert_eq!(fixed_recovery_iffts, 6_670);
    assert_eq!(fixed_recovery_butterflies, 33_221_509_120);
    let commitment_forward_butterflies =
        2 * columns * (layout.common_lde_size() as u64 / 2) * u64::from(layout.common_lde_log2);
    assert_eq!(commitment_forward_butterflies, 536_208_211_968);
    eprintln!(
        "MAIN complete work inventory: quotient_rows={quotient_rows}, AIR_residues={residues}, quotient_native_IFFTs={quotient_native_iffts}, quotient_native_butterflies={quotient_native_butterflies}, quotient_forward_butterflies={quotient_forward_butterflies}, quotient_Fp4_inverse_butterflies={quotient_fp4_inverse_butterflies}, other_native_butterflies={other_native_butterflies}, fixed_native_butterflies={fixed_native_butterflies}, fixed_recovery_IFFTs={fixed_recovery_iffts}, fixed_recovery_butterflies={fixed_recovery_butterflies}, commitment_forward_butterflies={commitment_forward_butterflies}, masked_coefficient_cells={masked_cells}; public operation counts only, no timing or maximum-proof qualification"
    );
}

#[test]
fn grouped_deep_replay_fits_existing_buffers_and_eliminates_per_column_division() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let mut original_division_steps = 0_u64;
    let mut grouped_division_steps = 0_u64;
    for group in &layout.trace_groups {
        let coefficients = (1_usize << group.native_trace_log2) + MASK_DEGREE + 1;
        let width = group.base_width + group.aux_width;
        original_division_steps += (2 * width * (coefficients - 1)) as u64;
        grouped_division_steps += (2 * (coefficients - 1)) as u64;
        let owners = (2 + 2 * SECURITY_LANES) * coefficients * core::mem::size_of::<E>()
            + aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1
                * coefficients
                * core::mem::size_of::<F>();
        assert!(owners <= plan.replay_batch);
    }
    assert_eq!(plan.replay_batch, 310_494_720);
    // Each of the two evaluations divides every masked polynomial once;
    // synthetic division uses one fewer recurrence step than coefficients.
    assert_eq!(original_division_steps, 2 * (2_127_275_976 - 5_811));
    assert_eq!(original_division_steps, 4_254_540_330);
    assert_eq!(grouped_division_steps, 1_791_828);
    assert_eq!(
        4 * ((1 << 19) + MASK_DEGREE + 1) * core::mem::size_of::<E>()
            + 8 * ((1 << 19) + MASK_DEGREE + 1) * core::mem::size_of::<F>(),
        101_011_968
    );
    // Individual claims still require both dot products, and both weighted
    // coefficients still require scale-by-base-field work for every cell.
    // This is an operation inventory, not a full-proof timing estimate.
    eprintln!(
        "MAIN DEEP synthetic-division recurrence steps: original={original_division_steps}, grouped={grouped_division_steps}; each individual claim remains checked, base-field weighted sums remain"
    );
}

#[test]
fn registration_quotient_phase_ledger_retains_originals_chunks_and_growth() {
    use main_resources::MainRegistrationQuotientPayloadV1;
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let cap = layout
        .as_shared()
        .unwrap()
        .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
        .unwrap();
    let mut saw_fixed_growth = false;
    for registration in &layout.registered_segments {
        let segment = registration.segment;
        let plan = registered_retained_prover_plan_v1(segment, layout.common_lde_log2).unwrap();
        let stripe_rows = plan.quotient_coset_rows.min(1 << 19);
        let actual =
            MainRegistrationQuotientPayloadV1::new_v1(&layout, *registration, cap).unwrap();
        let width = segment.base_width + segment.aux_width + segment.fixed_width;
        let metadata = width * core::mem::size_of::<Vec<F>>()
            + SECURITY_LANES * core::mem::size_of::<Vec<E>>()
            + 2 * SECURITY_LANES * core::mem::size_of::<Vec<Vec<E>>>()
            + 2 * SECURITY_LANES * COMPOSITION_DEGREE_CHUNKS * core::mem::size_of::<Vec<E>>()
            + aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 * core::mem::size_of::<&mut [F]>()
            + 2 * super::super::super::p256_aggregate_adapter::P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1 * core::mem::size_of::<F>()
            + 16 * core::mem::size_of::<usize>()
            + main_quotient_denominators::MainQuotientDenominatorsV1::payload_bound_v1(
                segment.trace_log2,
                main_quotient_stripes::MainQuotientStripeV1::new_v1(segment.trace_log2, plan.quotient_coset_log2, 0).unwrap(),
            ).unwrap();
        let quotients = SECURITY_LANES * plan.quotient_coset_rows * core::mem::size_of::<E>();
        let copy = plan.quotient_coset_rows * core::mem::size_of::<E>();
        let chunks = SECURITY_LANES * COMPOSITION_DEGREE_CHUNKS * cap * core::mem::size_of::<E>();
        let growth = if stripe_rows > segment.trace_size() {
            saw_fixed_growth = true;
            segment.trace_size() * core::mem::size_of::<F>()
        } else {
            0
        };
        assert_eq!(
            actual.stripe,
            metadata
                + width * stripe_rows * core::mem::size_of::<F>()
                + growth
                + quotients
                + chunks
        );
        assert_eq!(
            actual.interpolation,
            metadata + quotients + copy + 2 * chunks
        );
        assert_eq!(
            actual.accumulation,
            metadata + 2 * chunks + cap * core::mem::size_of::<E>()
        );
        assert_eq!(
            actual.maximum_v1(),
            [actual.stripe, actual.interpolation, actual.accumulation]
                .into_iter()
                .max()
                .unwrap()
        );
        assert!(
            MainRegistrationQuotientPayloadV1::new_v1(&layout, *registration, usize::MAX).is_err()
        );
    }
    assert!(saw_fixed_growth);
}

#[test]
fn current_registration_resource_owner_plan_diagnostic() {
    use main_resources::MainRegistrationQuotientPayloadV1;
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
    let joint = main_ca_resources::MainCaJointBufferPlanV1::new_v1(&layout).unwrap();
    let cap = layout
        .as_shared()
        .unwrap()
        .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
        .unwrap();
    eprintln!("MAIN current owner-plan diagnostic: {plan:?}; joint={joint:?}");
    let mut maximum = 0;
    for (index, registration) in layout.registered_segments.iter().enumerate() {
        let phases =
            MainRegistrationQuotientPayloadV1::new_v1(&layout, *registration, cap).unwrap();
        let ordinary = plan.quotient_cache_plan_v1(&layout, *registration).unwrap();
        let joint_cache = joint
            .quotient_cache_plan_v1(&layout, *registration)
            .unwrap();
        maximum = maximum.max(phases.maximum_v1());
        eprintln!(
            "MAIN current registration-owner diagnostic: index={index}, registration={registration:?}, phases={phases:?}, ordinary_cache={ordinary:?}, joint_cache={joint_cache:?}"
        );
    }
    assert_eq!(maximum, plan.quotient_stage);
    for phase in [
        main_ca_resources::MainCaBufferPhaseV1::OriginalCommitments,
        main_ca_resources::MainCaBufferPhaseV1::Registration,
        main_ca_resources::MainCaBufferPhaseV1::PrivateLinks,
        main_ca_resources::MainCaBufferPhaseV1::Finalization,
    ] {
        eprintln!(
            "MAIN current joint-phase diagnostic: phase={phase:?}, required={}",
            joint.required_v1(phase).unwrap()
        );
    }
    // This is source-derived allocation arithmetic only. Original numeric pins,
    // complete native proof/RSS and all external limits remain separate gates.
    assert_eq!(plan.maximum_live_buffers, 3_697_993_184);
}
