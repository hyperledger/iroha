//! Complete MAIN constraint evaluation at the transcript's Fp4 DEEP point.
//!
//! Fixed values come from the same closed public schedules as scalar queries.
//! Every logical registration contributes its full quotient with its native
//! vanishing polynomial. This complete relation check precedes authenticated
//! current-row DEEP and FRI query verification under the selected proof profile.

use super::*;

/// Exact native-subgroup Lagrange weights at an extension-field point.
/// The largest allocation is one public native column, never a fixed matrix.
fn lagrange_weights_v1(trace_log2: u8, point: E) -> Result<Vec<E>, ZkX509StarkErrorV1> {
    if trace_log2 == 0 || trace_log2 > ZK_X509_MAX_NATIVE_TRACE_LOG2_V1 || !point.is_canonical() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let rows = 1_usize << trace_log2;
    let root = goldilocks_primitive_root_v1(trace_log2).map_err(map_transparent_error_v1)?;
    let vanishing = point.pow(rows as u128).sub(E::ONE);
    if vanishing == E::ZERO {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let factor = vanishing.mul_base(
        F(rows as u64)
            .inv()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?,
    );
    let mut weights = Vec::new();
    weights
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    let mut native = F::ONE;
    for _ in 0..rows {
        weights.push(point.sub(E::from_base(native)));
        native = native.mul(root);
    }
    aggregate::batch_invert_fp4_nonzero_v1(&mut weights).map_err(map_aggregate_error_v1)?;
    native = F::ONE;
    let mut sum = E::ZERO;
    for weight in &mut weights {
        *weight = weight.mul(factor).mul_base(native);
        sum = sum.add(*weight);
        native = native.mul(root);
    }
    if native != F::ONE || sum != E::ONE {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(weights)
}

/// Bounded public row replay for the smaller fixed schedules.
fn fixed_rows_at_point_v1<R: AsRef<[F]>>(
    trace_log2: u8,
    width: usize,
    point: E,
    mut row: impl FnMut(usize) -> Result<R, ZkX509StarkErrorV1>,
) -> Result<Vec<E>, ZkX509StarkErrorV1> {
    if width == 0 || width > ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let weights = lagrange_weights_v1(trace_log2, point)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(width)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    result.resize(width, E::ZERO);
    for (index, weight) in weights.into_iter().enumerate() {
        let native = row(index)?;
        let native = native.as_ref();
        if native.len() != width || native.iter().any(|value| !value.is_canonical()) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        for (target, value) in result.iter_mut().zip(native) {
            *target = target.add(weight.mul_base(*value));
        }
    }
    Ok(result)
}

/// Evaluate the compiled public affine schedule at z and omega*z together.
/// Rotating Lagrange weights by one gives the exact next native row polynomial.
fn log19_public_at_point_v1(
    schedule: &MainLog19PublicFixedAffineScheduleV1,
    point: E,
) -> Result<Box<[MainLog19VerifierGeneratedFixedOpeningV1<E>; 2]>, ZkX509StarkErrorV1> {
    schedule.validate_v1()?;
    // Keep the exact current/next pair heap-owned across this return and the
    // prepared verifier context; reserve before doing any interpolation work.
    let mut openings = Vec::new();
    openings
        .try_reserve_exact(2)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    let weights = lagrange_weights_v1(ZK_X509_MAX_NATIVE_TRACE_LOG2_V1, point)?;
    let (prefix, linear) = main_log19_weight_prefixes_v1(&weights)?;
    let mut combined = [[E::ZERO; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1]; 2];
    for segment in &schedule.segments {
        for (shift, row) in combined.iter_mut().enumerate() {
            let value =
                main_log19_shifted_affine_segment_sum_v1(&prefix, &linear, shift, *segment)?;
            let target = row
                .get_mut(usize::from(segment.column))
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
            *target = target.add(value);
        }
    }
    for (shift, row) in combined.iter().enumerate() {
        openings.push(main_log19_generated_fixed_opening_v1(
            main_log19_der_fixed_opening_from_prefix_v1(&weights, &prefix, shift)?,
            *row,
        ));
    }
    openings
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)
}

fn opened_rows_v1<'a>(
    registration: RegisteredSegmentLayoutV1,
    groups: &'a [aggregate::AggregateOpenedDeepTraceGroupV1],
) -> Result<RegisteredOpenedRowsV1<'a, E>, ZkX509StarkErrorV1> {
    let group = groups
        .get(registration.trace_group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let base = registration.base_start..registration.base_end()?;
    let aux = registration.aux_start..registration.aux_end()?;
    Ok(RegisteredOpenedRowsV1 {
        base_current: group
            .base_current
            .get(base.clone())
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
        base_next: group
            .base_next
            .get(base)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
        aux_current: group
            .aux_current
            .get(aux.clone())
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
        aux_next: group
            .aux_next
            .get(aux)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
    })
}

fn quotient_v1(
    segment: SegmentLayoutV1,
    point: E,
    residues: &[E],
    alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    if residues.len() != segment.constraint_count
        || alphas.len() != segment.constraint_count
        || residues
            .iter()
            .chain(alphas)
            .any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let inverse = point
        .pow(segment.trace_size() as u128)
        .sub(E::ONE)
        .inv()
        .ok_or(ZkX509StarkErrorV1::ConstraintOpening)?;
    Ok(residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |sum, (residue, alpha)| {
            sum.add(residue.mul(*alpha))
        })
        .mul(inverse))
}

fn verify_composition_v1(
    layout: &aggregate::AggregateProofLayoutV1,
    deep: &aggregate::AggregateDeepProofV1,
    point: E,
    expected: E,
) -> Result<(), ZkX509StarkErrorV1> {
    if deep.composition_values.len() != SECURITY_LANES || SECURITY_LANES != 1 {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let chunks =
        aggregate::canonical_fp4_fields_v1(&deep.composition_values[0], COMPOSITION_DEGREE_CHUNKS)
            .map_err(map_aggregate_error_v1)?;
    let power = point.pow(
        crate::privacy_engines::zk_x509::composition_masking::QuotientChunkGeometryV1::new_v1(
            layout,
            AGGREGATE_PARAMETERS_V1,
        )
        .map_err(map_aggregate_error_v1)?
        .stride_v1() as u128,
    );
    let actual = chunks
        .iter()
        .rev()
        .fold(E::ZERO, |sum, chunk| sum.mul(power).add(*chunk));
    if actual != expected {
        #[cfg(test)]
        super::super::super::engine::prover_diagnostic::record_public_verifier_error_v1(
            "main-oods-composition-equality",
            &(point, actual, expected),
        );
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    Ok(())
}

/// Verifier-owned fixed evaluations, prepared once for this exact DEEP point.
/// This private owner cannot be supplied by a proof or external caller.
struct MainDeepFixedV1 {
    point: E,
    public: Box<[MainLog19VerifierGeneratedFixedOpeningV1<E>; 2]>,
    sha_current: [[E; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]; ZK_X509_SHA_SEGMENT_COUNT_V1],
    sha_next: [[E; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]; ZK_X509_SHA_SEGMENT_COUNT_V1],
    rows: Vec<Vec<E>>,
}

fn prepare_main_deep_fixed_v1(
    layout: &AggregateProofLayoutV1,
    point: E,
    p256: &MainP256Log5VerifierConstraintSourceV1<'_>,
    projection: &MainProjectionVerifierConstraintSourceV1,
    io: &MainIoVerifierConstraintSourceV1,
    log19: &MainLog19VerifierConstraintSourceV1,
) -> Result<MainDeepFixedV1, ZkX509StarkErrorV1> {
    let public = log19_public_at_point_v1(
        log19
            .public_fixed
            .as_ref()
            .ok_or(ZkX509StarkErrorV1::TranscriptMismatch)?,
        point,
    )?;
    let root19 = goldilocks_primitive_root_v1(ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
        .map_err(map_transparent_error_v1)?;
    let next_point = point.mul_base(root19);
    let sha_schedule = zk_x509_sha_fixed_algebraic_schedule_v1(log19.sha_shape)
        .map_err(map_sha_fixed_algebraic_error_v1)?;
    let sha_current = expand_main_log19_sha_fixed_opening_v1(
        &sha_schedule
            .evaluate_extension_point_v1(point)
            .map_err(map_fixed_algebraic_error_v1)?,
        &public[0],
    )?;
    let sha_next = expand_main_log19_sha_fixed_opening_v1(
        &sha_schedule
            .evaluate_extension_point_v1(next_point)
            .map_err(map_fixed_algebraic_error_v1)?,
        &public[1],
    )?;
    let p256_combined = zk_x509_p256_fixed_algebraic_schedule_v1()
        .map_err(map_p256_fixed_algebraic_error_v1)?
        .evaluate_extension_point_v1(point)
        .map_err(map_fixed_algebraic_error_v1)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(layout.registered_segments.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for registration in layout.registered_segments.iter().copied() {
        let evaluator = MainFp4AirEvaluatorV1::for_registration_v1(registration)?
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let fixed = match evaluator {
            MainFp4AirEvaluatorV1::P256(_) => {
                let identity = p256_main_registration_from_main_layout_v1(registration)?;
                if registration.segment.trace_log2 == ZK_X509_MAX_NATIVE_TRACE_LOG2_V1 {
                    let kind = super::super::super::fixed_algebraic_p256::zk_x509_p256_fixed_algebraic_schedule_for_registration_v1(identity)
                        .map_err(map_p256_fixed_algebraic_error_v1)?;
                    let (start, width) = kind.start_width_v1();
                    if width != registration.segment.fixed_width
                        || p256_combined.len() != ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1
                    {
                        return Err(ZkX509StarkErrorV1::ProfileMismatch);
                    }
                    p256_combined
                        .get(start..start + width)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                        .to_vec()
                } else {
                    fixed_rows_at_point_v1(
                        registration.segment.trace_log2,
                        registration.segment.fixed_width,
                        point,
                        |row| {
                            p256.fixed
                                .fixed_row_v1(identity, row)
                                .map_err(ZkX509StarkErrorV1::from)
                        },
                    )?
                }
            }
            MainFp4AirEvaluatorV1::Projection(_) => fixed_rows_at_point_v1(
                registration.segment.trace_log2,
                registration.segment.fixed_width,
                point,
                |row| {
                    projection
                        .fixed_rows
                        .get(row)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
                },
            )?,
            MainFp4AirEvaluatorV1::ByteMemory(_) => fixed_rows_at_point_v1(
                registration.segment.trace_log2,
                registration.segment.fixed_width,
                point,
                |row| io.fixed_schedule.fixed_row_v1(row),
            )?,
            MainFp4AirEvaluatorV1::StrictDer(_) => public[0].der.to_vec(),
            MainFp4AirEvaluatorV1::Rfc5280(_) => public[0].rfc.to_vec(),
            MainFp4AirEvaluatorV1::Sha(_) => sha_current
                .get(usize::from(registration.segment.instance))
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                .to_vec(),
        };
        if fixed.len() != registration.segment.fixed_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        rows.push(fixed);
    }
    Ok(MainDeepFixedV1 {
        point,
        public,
        sha_current,
        sha_next,
        rows,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn main_deep_composition_v1(
    layout: &AggregateProofLayoutV1,
    groups: &[aggregate::AggregateOpenedDeepTraceGroupV1],
    point: E,
    alphas: &[Vec<Vec<E>>],
    link_alphas: &[E],
    p256: &MainP256Log5VerifierConstraintSourceV1<'_>,
    projection: &MainProjectionVerifierConstraintSourceV1,
    io: &MainIoVerifierConstraintSourceV1,
    log19: &MainLog19VerifierConstraintSourceV1,
    prepared: &MainDeepFixedV1,
) -> Result<E, ZkX509StarkErrorV1> {
    if point != prepared.point || prepared.rows.len() != layout.registered_segments.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut expected = E::ZERO;
    for (index, registration) in layout.registered_segments.iter().copied().enumerate() {
        let opening = opened_rows_v1(registration, groups)?;
        let evaluator = MainFp4AirEvaluatorV1::for_registration_v1(registration)?
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if evaluator.registration_v1() != registration {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues = match evaluator {
            MainFp4AirEvaluatorV1::P256(evaluator) => {
                p256_main_registration_from_main_layout_v1(registration)?;
                let fixed = &prepared.rows[index];
                evaluator.evaluate_residues_v1(opening, fixed, p256.challenges)?
            }
            MainFp4AirEvaluatorV1::Projection(evaluator) => {
                if registration != projection.registration {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let fixed = &prepared.rows[index];
                evaluator.evaluate_residues_v1(opening, fixed, projection.challenges)?
            }
            MainFp4AirEvaluatorV1::ByteMemory(evaluator) => {
                if registration != io.registration {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let fixed = &prepared.rows[index];
                evaluator.evaluate_residues_v1(
                    io.fixed_schedule.logical_active_rows,
                    opening,
                    fixed,
                    io.challenges,
                )?
            }
            MainFp4AirEvaluatorV1::StrictDer(evaluator) => evaluator.evaluate_residues_v1(
                opening,
                &prepared.public[0].der,
                &prepared.public[1].der,
                DerMainFp4AirContextV1 {
                    challenges: log19.post_base.der(),
                    public: log19.der_public,
                },
            )?,
            MainFp4AirEvaluatorV1::Rfc5280(evaluator) => evaluator.evaluate_residues_v1(
                opening,
                &prepared.public[0].rfc,
                RfcMainFp4AirContextV1 {
                    der: log19.post_base.der(),
                    rfc: *log19.post_base.rfc5280(),
                },
            )?,
            MainFp4AirEvaluatorV1::Sha(evaluator) => {
                let segment = usize::from(registration.segment.instance);
                let current = ZkX509ShaBatchRowV1 {
                    base: opening
                        .base_current
                        .try_into()
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    aux: opening
                        .aux_current
                        .try_into()
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    fixed: *prepared
                        .sha_current
                        .get(segment)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                };
                let next = ZkX509ShaBatchRowV1 {
                    base: opening
                        .base_next
                        .try_into()
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    aux: opening
                        .aux_next
                        .try_into()
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    fixed: *prepared
                        .sha_next
                        .get(segment)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                };
                evaluator.evaluate_residues_v1(
                    &current,
                    &next,
                    ShaMainFp4AirContextV1 {
                        word: log19.post_base.sha_word(),
                        call: log19.post_base.sha(),
                        rfc: *log19.post_base.rfc5280(),
                        segment: segment as u8,
                    },
                )?
            }
        };
        expected = expected.add(quotient_v1(
            registration.segment,
            point,
            &residues,
            &alphas[index][0],
        )?);
    }
    Ok(expected.add(
        main_terminal_links::MainTerminalLinkPlanV1::new_v1(layout)?.evaluate_v1(
            groups,
            point,
            link_alphas,
        )?,
    ))
}

/// Check isolated MAIN component fixtures using only verifier-owned context.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[cfg(test)]
pub(super) fn verify_main_deep_constraints_v1(
    layout: &AggregateProofLayoutV1,
    deep: &aggregate::AggregateDeepProofV1,
    point: E,
    alphas: &[Vec<Vec<E>>],
    link_alphas: &[E],
    key_plan: &main_key_joins::MainKeyJoinPlanV1,
    key_alphas: &[E],
    key_openings: &[E; main_key_joins::OPENINGS_V1],
    sha_union_plan: &main_sha_union::MainShaUnionPlanV1,
    sha_union_alphas: &[E],
    p256: &MainP256Log5VerifierConstraintSourceV1<'_>,
    projection: &MainProjectionVerifierConstraintSourceV1,
    io: &MainIoVerifierConstraintSourceV1,
    log19: &MainLog19VerifierConstraintSourceV1,
) -> Result<(), ZkX509StarkErrorV1> {
    verify_main_deep_constraints_with_ca_v1(
        layout,
        deep,
        point,
        alphas,
        link_alphas,
        key_plan,
        key_alphas,
        key_openings,
        sha_union_plan,
        sha_union_alphas,
        p256,
        projection,
        io,
        log19,
        None,
    )
}

/// Check the complete local relation and the verifier-owned original CA joins.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn verify_main_deep_constraints_with_ca_v1(
    layout: &AggregateProofLayoutV1,
    deep: &aggregate::AggregateDeepProofV1,
    point: E,
    alphas: &[Vec<Vec<E>>],
    link_alphas: &[E],
    key_plan: &main_key_joins::MainKeyJoinPlanV1,
    key_alphas: &[E],
    key_openings: &[E; main_key_joins::OPENINGS_V1],
    sha_union_plan: &main_sha_union::MainShaUnionPlanV1,
    sha_union_alphas: &[E],
    p256: &MainP256Log5VerifierConstraintSourceV1<'_>,
    projection: &MainProjectionVerifierConstraintSourceV1,
    io: &MainIoVerifierConstraintSourceV1,
    log19: &MainLog19VerifierConstraintSourceV1,
    ca: Option<main_joint::MainCaOpenedContributionV1<'_>>,
) -> Result<(), ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    let shared = layout.as_shared()?;
    if !aggregate::deep_point_is_admissible_v1(point, AGGREGATE_PARAMETERS_V1, &shared)
        .map_err(map_aggregate_error_v1)?
        || alphas.len() != layout.registered_segments.len()
        || alphas
            .iter()
            .zip(&layout.registered_segments)
            .any(|(lanes, registration)| {
                lanes.len() != SECURITY_LANES
                    || lanes.iter().any(|lane| {
                        lane.len() != registration.segment.constraint_count
                            || lane.iter().any(|value| !value.is_canonical())
                    })
            })
    {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let groups = aggregate::canonical_deep_trace_groups_v1(deep, AGGREGATE_PARAMETERS_V1, &shared)
        .map_err(map_aggregate_error_v1)?;
    let prepared = prepare_main_deep_fixed_v1(layout, point, p256, projection, io, log19)
        .inspect_err(|_error| {
            #[cfg(test)]
            super::super::super::engine::prover_diagnostic::record_public_verifier_error_v1(
                "main-oods-fixed-evaluation",
                _error,
            );
        })?;
    let expected = main_deep_composition_v1(
        layout,
        &groups,
        point,
        alphas,
        link_alphas,
        p256,
        projection,
        io,
        log19,
        &prepared,
    )
    .inspect_err(|_error| {
        #[cfg(test)]
        super::super::super::engine::prover_diagnostic::record_public_verifier_error_v1(
            "main-oods-residues",
            _error,
        );
    })?;
    if !key_plan.admissible_v1(point, &shared)? {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let expected = expected.add(key_plan.evaluate_v1(&groups, point, key_openings, key_alphas)?);
    if sha_union_plan != &main_sha_union::MainShaUnionPlanV1::new_v1(layout)? {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let expected = expected.add(sha_union_plan.evaluate_v1(&groups, point, sha_union_alphas)?);
    let expected = if let Some(ca) = ca {
        expected.add(ca.plan.evaluate_v1(
            &groups,
            point,
            ca.alphas,
            &ca.openings.main,
            &ca.openings.ca,
        )?)
    } else {
        expected
    };
    verify_composition_v1(&shared, deep, point, expected)
}

#[cfg(test)]
#[path = "main_oods_tests.rs"]
mod tests;

/// Check the complete standalone DER AIR, including all eight public endpoints.
/// The reduced wire authenticates both z and omega*z through the unchanged DEEP
/// quotient; no caller-supplied fixed values or omitted query callback is trusted.
#[cfg(test)]
pub(in super::super) fn verify_standalone_der_oods_v1(
    layout: &AggregateProofLayoutV1,
    deep: &aggregate::AggregateDeepProofV1,
    point: E,
    challenges: ZkX509DerStarkChallengesV1,
    public: ZkX509DerStarkPublicTerminalsV1,
    claims: ZkX509DerStarkTerminalClaimsV1,
    alphas: &[Vec<E>],
) -> Result<(), ZkX509StarkErrorV1> {
    let segment = SegmentLayoutV1::for_der(ZkX509DerStarkShapeV1.active_rows())?;
    if layout.registered_segments.len() != 1
        || layout.trace_groups.len() != 1
        || layout.registered_segments[0].segment != segment
        || alphas.len() != SECURITY_LANES
        || alphas
            .iter()
            .any(|lane| lane.len() != segment.constraint_count)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    layout.validate()?;
    let shared = layout.as_shared()?;
    if !point.is_canonical()
        || !aggregate::deep_point_is_admissible_v1(point, layout.parameters_v1(), &shared)
            .map_err(map_aggregate_error_v1)?
    {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let (groups, compositions) = canonical_deep_values_v1(deep, layout)?;
    if groups.len() != 1 || compositions.len() != SECURITY_LANES {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let opening = &groups[0];
    let weights = lagrange_weights_v1(segment.trace_log2, point)?;
    let (prefix, _) = main_log19_weight_prefixes_v1(&weights)?;
    let fixed = main_log19_der_fixed_opening_from_prefix_v1(&weights, &prefix, 0)?;
    let next_fixed = main_log19_der_fixed_opening_from_prefix_v1(&weights, &prefix, 1)?;
    DER_FIXED_OPENING_EVALUATIONS_V1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let residues = evaluate_zk_x509_der_stark_residues_v1(
        opening
            .base_current
            .as_slice()
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        opening
            .base_next
            .as_slice()
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        opening
            .aux_current
            .as_slice()
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        opening
            .aux_next
            .as_slice()
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        &fixed,
        &next_fixed,
        challenges,
        public,
        claims,
    )
    .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
    // Standalone DER uses the original unmasked coefficient chunks, whose
    // stride is the full exclusive FRI cap. MAIN's masked chunk stride differs.
    let chunk_power = point.pow(
        shared
            .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
            .map_err(map_aggregate_error_v1)? as u128,
    );
    for (values, lane_alphas) in compositions.iter().zip(alphas) {
        let expected = quotient_v1(segment, point, &residues, lane_alphas)?;
        let actual = values
            .iter()
            .rev()
            .fold(E::ZERO, |sum, value| sum.mul(chunk_power).add(*value));
        if actual != expected {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
    }
    Ok(())
}
