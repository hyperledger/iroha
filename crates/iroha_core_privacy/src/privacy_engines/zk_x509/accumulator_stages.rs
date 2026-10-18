//! Staged original CA commitments with no retained commitment-domain LDE.
//!
//! The joint X5S1 engine owns the cryptographic entropy session. These phases
//! consume that session through explicit calls and keep the original masked
//! coefficients available for the later MAIN cross-proof quotient pass.

use super::super::credential_pre_aux::ZkX509CredentialPreAuxBindingV1;
use super::super::private_table::{PrivateTableV1, zeroize_fields_v1};
use super::private_links::{CA_EXTRA_OPENINGS_V1, CaMainPrivateLinkPlanV1};
use super::retained_columns::{CaColumnFamilyV1, CaOriginalMaskedColumnsV1};
use super::*;
use rand::TryRngCore;

fn clear_columns_v1(columns: &mut [Vec<F>]) {
    for column in columns {
        zeroize_fields_v1(column);
    }
}
struct CaAuxScratchV1 {
    base: [F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
    current: [F; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
    previous: [F; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
}
impl CaAuxScratchV1 {
    fn zero_v1() -> Self {
        Self {
            base: [F::ZERO; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
            current: [F::ZERO; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
            previous: [F::ZERO; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
        }
    }
}
impl Drop for CaAuxScratchV1 {
    fn drop(&mut self) {
        zeroize_fields_v1(&mut self.base);
        zeroize_fields_v1(&mut self.current);
        zeroize_fields_v1(&mut self.previous);
    }
}
/// Build native base columns with clearing ownership before any private row copy.
fn native_base_columns_v1(
    trace: &ZkX509CaAccumulatorTraceV1,
) -> Result<PrivateTableV1<Vec<F>>, ZkX509CaAccumulatorProofErrorV1> {
    trace
        .validate()
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
    let mut columns = PrivateTableV1::new(
        allocate_columns_v1(
            ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
            ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
        )
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?,
        clear_columns_v1,
    );
    let mut scratch = CaAuxScratchV1::zero_v1();
    for index in 0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
        scratch.base = trace
            .base_row(index)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
        append_array_row_v1(&mut columns, &scratch.base)
            .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
    }
    Ok(columns)
}
/// Build only native auxiliary columns; no private terminal-product copies exist.
fn native_aux_columns_v1(
    trace: &ZkX509CaAccumulatorTraceV1,
    public: ZkX509CaAccumulatorStarkPublicV1,
    binding: ZkX509CredentialPreAuxBindingV1,
) -> Result<PrivateTableV1<Vec<F>>, ZkX509CaAccumulatorProofErrorV1> {
    trace
        .validate()
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
    binding
        .sha()
        .validate()
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
    binding
        .rfc5280()
        .validate()
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
    let mut columns = PrivateTableV1::new(
        allocate_columns_v1(
            ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
            ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
        )
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?,
        clear_columns_v1,
    );
    let mut scratch = CaAuxScratchV1::zero_v1();
    for index in 0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
        scratch.base = trace
            .base_row(index)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
        let fixed = compile_ca_accumulator_fixed_row_v1(index)
            .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
        scratch.current = build_aux_row_v1(
            public,
            &scratch.base,
            &fixed,
            if index == 0 {
                None
            } else {
                Some(&scratch.previous)
            },
            binding.sha(),
            binding.rfc5280(),
        )
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
        append_array_row_v1(&mut columns, &scratch.current)
            .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
        scratch.previous.copy_from_slice(&scratch.current);
    }
    Ok(columns)
}
fn commit_original_columns_v1(
    proof_instance: ZkX509ProofInstanceV1,
    source: &CaOriginalMaskedColumnsV1,
) -> Result<PrivacyOuterDigestV1, ZkX509CaAccumulatorProofErrorV1> {
    let lde = source.local_lde_v1()?;
    let (leaf, node) = match source.family_v1() {
        CaColumnFamilyV1::Base => (CA_BASE_LEAF_DOMAIN_V1, CA_BASE_NODE_DOMAIN_V1),
        CaColumnFamilyV1::Auxiliary => (CA_AUX_LEAF_DOMAIN_V1, CA_AUX_NODE_DOMAIN_V1),
    };
    let tree = aggregate::row_tree_v1(
        ca_domains_v1(proof_instance).digest_context,
        leaf,
        node,
        0,
        &lde,
        1 << ZK_X509_CA_FRI_LDE_LOG2_V1,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    Ok(tree.root())
}

/// Original CA trace commitments ready for joint auxiliary-root binding.
/// Only masked coefficients cross this boundary; full local LDEs are dropped.
pub struct CaAwaitingMainAuxiliaryV1 {
    public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: ZkX509ShaCallScheduleV1,
    base: CaOriginalMaskedColumnsV1,
    auxiliary: CaOriginalMaskedColumnsV1,
    trace_roots: [aggregate::AggregateTraceGroupProofV1; 1],
    binding: ZkX509CredentialPreAuxBindingV1,
    transcript: TransparentTranscriptV1,
    auxiliary_transcript_state: PrivacyOuterDigestV1,
}
impl core::fmt::Debug for CaAwaitingMainAuxiliaryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CaAwaitingMainAuxiliaryV1 { <private coefficients redacted> }")
    }
}
impl CaAwaitingMainAuxiliaryV1 {
    /// Exact retained original coefficients and inline phase state. The schedule,
    /// transcript, public statement and empty frontiers have no additional heap.
    pub(crate) fn payload_bound_v1() -> Result<usize, ZkX509CaAccumulatorProofErrorV1> {
        CaOriginalMaskedColumnsV1::payload_bound_v1(CaColumnFamilyV1::Base)?
            .checked_add(CaOriginalMaskedColumnsV1::payload_bound_v1(
                CaColumnFamilyV1::Auxiliary,
            )?)
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Self>()))
            .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)
    }

    /// Sole shared challenge capability derived after both original base roots.
    pub(crate) const fn binding_v1(&self) -> ZkX509CredentialPreAuxBindingV1 {
        self.binding
    }
    /// The actual original CA auxiliary commitment, needed before MAIN alphas.
    pub(crate) fn auxiliary_root_v1(&self) -> PrivacyOuterDigestV1 {
        self.trace_roots[0].aux_root
    }
    /// Exact resident coefficient owner payload across the MAIN composition pass.
    pub(crate) fn allocated_payload_bytes_v1(
        &self,
    ) -> Result<usize, ZkX509CaAccumulatorProofErrorV1> {
        self.base
            .allocated_payload_bytes_v1()?
            .checked_add(self.auxiliary.allocated_payload_bytes_v1()?)
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Self>()))
            .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)
    }
    /// Borrow one of the16 original auxiliary columns selected by the closed plan.
    pub(crate) fn link_column_v1(
        &self,
        column: usize,
    ) -> Result<&[F], ZkX509CaAccumulatorProofErrorV1> {
        if !(96..100).contains(&column) && !(116..128).contains(&column) {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        self.auxiliary.column_v1(column)
    }
    /// Open exactly the original CA polynomials selected by this phase's public plan.
    pub(crate) fn open_link_values_v1(
        &self,
        plan: &CaMainPrivateLinkPlanV1,
        point: E,
    ) -> Result<[E; CA_EXTRA_OPENINGS_V1], ZkX509CaAccumulatorProofErrorV1> {
        self.validate_link_plan_v1(plan, point)?;
        let mut values = [E::ZERO; CA_EXTRA_OPENINGS_V1];
        for (value, opening) in values.iter_mut().zip(plan.ca_openings_v1()) {
            *value = self.auxiliary.open_v1(
                usize::from(opening.column),
                point.mul_base(opening.multiplier),
            )?;
        }
        Ok(values)
    }

    /// Build the independently mixed divided differences for the original CA FRI.
    /// Nothing is transferred until every opening equals its synthetic remainder.
    pub(in crate::privacy_engines::zk_x509) fn link_deep_coefficients_v1(
        &self,
        plan: &CaMainPrivateLinkPlanV1,
        point: E,
        values: &[E],
        mixes: &[E],
    ) -> Result<PrivateTableV1<E>, ZkX509CaAccumulatorProofErrorV1> {
        self.validate_link_plan_v1(plan, point)?;
        if values.len() != CA_EXTRA_OPENINGS_V1
            || mixes.len() != CA_EXTRA_OPENINGS_V1
            || values
                .iter()
                .chain(mixes)
                .any(|value| !value.is_canonical())
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        fn erase(values: &mut [E]) {
            for value in values {
                value.zeroize_v1();
            }
        }
        let count = ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 + CA_MASK_DEGREE_V1 + 1;
        let mut deferred = PrivateTableV1::new(Vec::new(), erase);
        deferred
            .try_reserve_exact(count)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
        if deferred.capacity() != count {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        deferred.resize(count, E::ZERO);
        for (index, opening) in plan.ca_openings_v1().iter().enumerate() {
            let coefficients = self.link_column_v1(usize::from(opening.column))?;
            if coefficients.len() != count {
                return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
            }
            let target = point.mul_base(opening.multiplier);
            let mut carry = zeroize::Zeroizing::new(E::ZERO);
            for (degree, coefficient) in coefficients.iter().enumerate().rev() {
                deferred[degree] = deferred[degree].add((*carry).mul(mixes[index]));
                *carry = E::from_base(*coefficient).add((*carry).mul(target));
            }
            if *carry != values[index] {
                return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
            }
        }
        Ok(deferred)
    }

    /// Require the immutable plan for this original coefficient/challenge owner.
    pub(crate) fn validate_source_plan_v1(
        &self,
        plan: &CaMainPrivateLinkPlanV1,
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        self.validate_v1()?;
        if *plan != CaMainPrivateLinkPlanV1::new_v1(&self.schedule, self.binding.sha())? {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        Ok(())
    }

    fn validate_link_plan_v1(
        &self,
        plan: &CaMainPrivateLinkPlanV1,
        point: E,
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        self.validate_source_plan_v1(plan)?;
        if !plan.admissible_v1(point)? {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        Ok(())
    }

    /// Check phase provenance before its consuming joint-root transition.
    fn validate_v1(&self) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        if self.transcript.context() != self.binding.proof_instance_v1().ca_context_v1() {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        validate_ca_proof_public_v1(self.public, &self.schedule)?;
        if self.transcript.state() != self.auxiliary_transcript_state
            || self.trace_roots[0].base_root == PrivacyOuterDigestV1::default()
            || self.trace_roots[0].aux_root == PrivacyOuterDigestV1::default()
            || !self.trace_roots[0].base_frontier.is_empty()
            || !self.trace_roots[0].aux_frontier.is_empty()
            || self.base.family_v1() != CaColumnFamilyV1::Base
            || self.auxiliary.family_v1() != CaColumnFamilyV1::Auxiliary
            || self.allocated_payload_bytes_v1()? != Self::payload_bound_v1()?
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        Ok(())
    }
}

/// Commit original CA base and auxiliary polynomials around the shared X5B1.
/// The caller owns one health-checked cryptographic session for the whole proof.
pub fn commit_ca_through_auxiliary_v1<R: TryRngCore>(
    trace: &ZkX509CaAccumulatorTraceV1,
    schedule: &ZkX509ShaCallScheduleV1,
    main_pre_aux: ZkX509CredentialMainPreAuxV1,
    rng: &mut R,
) -> Result<CaAwaitingMainAuxiliaryV1, ZkX509CaAccumulatorProofErrorV1> {
    let proof_instance = main_pre_aux.proof_instance_v1();
    trace
        .validate()
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
    validate_ca_proof_schedule_v1(schedule)?;
    let public = ca_accumulator_stark_public_v1(trace, schedule)
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
    validate_ca_proof_public_v1(public, schedule)?;
    let request = ca_accumulator_resource_request_v1(
        ZK_X509_CA_ACCUMULATOR_REDUCED_AIR_DEGREE_V1,
        1,
        CA_QUERY_COUNT_V1,
    )
    .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
    let envelope = checked_ca_accumulator_resource_envelope_v1(request)
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
    if request.lde_log2 != ZK_X509_CA_FRI_LDE_LOG2_V1
        || envelope.mask_coefficients != CA_MASK_DEGREE_V1 + 1
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    let layout = ca_aggregate_layout_v1()?;
    let base = CaOriginalMaskedColumnsV1::sample_v1(
        CaColumnFamilyV1::Base,
        native_base_columns_v1(trace)?.into_vec(),
        rng,
    )?;
    let mut trace_roots = [aggregate::AggregateTraceGroupProofV1 {
        base_root: commit_original_columns_v1(proof_instance, &base)?,
        aux_root: PrivacyOuterDigestV1::default(),
        base_frontier: Vec::new(),
        aux_frontier: Vec::new(),
    }];
    let mut transcript = new_ca_transcript_v1(proof_instance, public, schedule, &layout)?;
    aggregate::absorb_base_roots_v1(
        &mut transcript,
        &ca_domains_v1(proof_instance),
        &trace_roots,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    let binding = derive_zk_x509_credential_pre_aux_binding_v1(
        main_pre_aux,
        ca_profile_digest_v1()?,
        ca_public_digest_v1(proof_instance, public, schedule)?,
        trace_roots[0].base_root,
    )
    .map_err(map_credential_pre_aux_error_v1)?;
    absorb_zk_x509_credential_pre_aux_binding_v1(&mut transcript, binding)
        .map_err(map_credential_pre_aux_error_v1)?;
    let auxiliary = CaOriginalMaskedColumnsV1::sample_v1(
        CaColumnFamilyV1::Auxiliary,
        native_aux_columns_v1(trace, public, binding)?.into_vec(),
        rng,
    )?;
    trace_roots[0].aux_root = commit_original_columns_v1(proof_instance, &auxiliary)?;
    aggregate::absorb_aux_roots_v1(
        &mut transcript,
        &ca_domains_v1(proof_instance),
        &trace_roots,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    let phase = CaAwaitingMainAuxiliaryV1 {
        public,
        schedule: schedule.clone(),
        base,
        auxiliary,
        trace_roots,
        binding,
        auxiliary_transcript_state: transcript.state(),
        transcript,
    };
    phase.validate_v1()?;
    Ok(phase)
}

// The sole completion route consumes both original-root owners through the
// joint auxiliary-root, composition, shared-point DEEP and FRI stages.

#[cfg(test)]
#[path = "accumulator_stages_tests.rs"]
mod tests;

/// Clearing fixed-size row scratch for the original CA local composition.
struct CaLocalRowsV1 {
    base: [F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
    next_base: [F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
    aux: [F; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
    next_aux: [F; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
    fixed: [F; ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1],
}
impl CaLocalRowsV1 {
    fn zero_v1() -> Self {
        Self {
            base: [F::ZERO; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
            next_base: [F::ZERO; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
            aux: [F::ZERO; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
            next_aux: [F::ZERO; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1],
            fixed: [F::ZERO; ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1],
        }
    }
}
impl Drop for CaLocalRowsV1 {
    fn drop(&mut self) {
        zeroize_fields_v1(&mut self.base);
        zeroize_fields_v1(&mut self.next_base);
        zeroize_fields_v1(&mut self.aux);
        zeroize_fields_v1(&mut self.next_aux);
        zeroize_fields_v1(&mut self.fixed);
    }
}

impl CaAwaitingMainAuxiliaryV1 {
    /// Build the local quotient from these original committed polynomials.
    /// Only the joint auxiliary-root transition may supply these alphas in the
    /// completed engine. This helper neither finalizes nor publishes a proof.
    pub(super) fn local_composition_v1<R: TryRngCore>(
        &self,
        alphas: &[E],
        rng: &mut R,
    ) -> Result<CaCompositionLanesV1, ZkX509CaAccumulatorProofErrorV1> {
        self.validate_v1()?;
        let constraint_count = ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1;
        if alphas.len() != constraint_count || alphas.iter().any(|value| !value.is_canonical()) {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        let layout = ca_aggregate_layout_v1()?;
        let rows = layout.common_lde_size();
        if rows != 65_536 || ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 != 4096 {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        let root = goldilocks_primitive_root_v1(ZK_X509_CA_FRI_LDE_LOG2_V1)
            .map_err(map_transparent_proof_error_v1)?;
        // (g*omega^i)^4096 repeats every16 rows. These public denominators
        // need only16 inversions, never one inversion for each local-LDE row.
        let inverses = ca_local_vanishing_inverses_v1(root)?;
        let evaluations = {
            let base = self.base.local_lde_v1()?;
            let aux = self.auxiliary.local_lde_v1()?;
            let fixed = ca_fixed_lde_columns_v1(
                &compile_ca_accumulator_fixed_columns_v1()
                    .map_err(ZkX509CaAccumulatorProofErrorV1::from)?,
            )?;
            if fixed.len() != ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1
                || fixed
                    .iter()
                    .any(|column| column.len() != rows || column.capacity() != rows)
            {
                return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
            }
            let mut evaluations = PrivateTableV1::new(Vec::new(), |values: &mut [E]| {
                super::super::private_table::zeroize_words_v1(values);
            });
            evaluations
                .try_reserve_exact(rows)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
            if evaluations.capacity() != rows {
                return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
            }
            check_ca_working_payload_v1(&[
                ca_matrix_payload_v1(&base, base.capacity())?,
                ca_matrix_payload_v1(&aux, aux.capacity())?,
                ca_matrix_payload_v1(&fixed, fixed.capacity())?,
                evaluations.capacity() * core::mem::size_of::<E>(),
                core::mem::size_of::<CaLocalRowsV1>(),
                ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1 * core::mem::size_of::<F>(),
                core::mem::size_of::<E>(),
            ])?;
            let mut scratch = CaLocalRowsV1::zero_v1();
            for index in 0..rows {
                let next = (index + 16) % rows;
                for (column, values) in base.iter().enumerate() {
                    scratch.base[column] = values[index];
                    scratch.next_base[column] = values[next];
                }
                for (column, values) in aux.iter().enumerate() {
                    scratch.aux[column] = values[index];
                    scratch.next_aux[column] = values[next];
                }
                for (column, values) in fixed.iter().enumerate() {
                    scratch.fixed[column] = values[index];
                }
                let residues = PrivateTableV1::new(
                    evaluate_ca_accumulator_local_residues_v1(
                        self.public,
                        &scratch.base,
                        &scratch.next_base,
                        &scratch.aux,
                        &scratch.next_aux,
                        &scratch.fixed,
                        self.binding.sha(),
                        self.binding.rfc5280(),
                    )
                    .map_err(ZkX509CaAccumulatorProofErrorV1::from)?,
                    zeroize_fields_v1,
                );
                if residues.len() != constraint_count
                    || residues.capacity() > ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1
                {
                    return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
                }
                let mut quotient = zeroize::Zeroizing::new(E::ZERO);
                for (residue, alpha) in residues.iter().zip(alphas) {
                    *quotient = (*quotient).add(alpha.mul_base(*residue));
                }
                evaluations.push((*quotient).mul_base(inverses[index % 16]));
            }
            evaluations
        };
        // Original LDE matrices and every row/residue scratch owner have dropped
        // before the quotient IFFT, adjacent masks and four output codewords.
        let geometry = super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
            &layout,
            CA_AGGREGATE_PARAMETERS_V1,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let chunks = geometry
            .split_evaluations_v1(evaluations.into_vec(), layout.common_lde_log2(), rng)
            .map_err(map_aggregate_proof_error_v1)?;
        own_ca_composition_lane_v1(chunks)
    }
}

fn ca_local_vanishing_inverses_v1(root: F) -> Result<[F; 16], ZkX509CaAccumulatorProofErrorV1> {
    if root
        != goldilocks_primitive_root_v1(ZK_X509_CA_FRI_LDE_LOG2_V1)
            .map_err(map_transparent_proof_error_v1)?
        || ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 != 4096
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    let mut x = F(GOLDILOCKS_GENERATOR_V1);
    let mut result = [F::ZERO; 16];
    for value in &mut result {
        *value = x
            .pow(4096)
            .sub(F::ONE)
            .inv()
            .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
        x = x.mul(root);
    }
    Ok(result)
}

#[path = "accumulator_joint_prover.rs"]
pub mod joint;

/// CA working owners fit inside, never above, the MAIN joint arithmetic plan.
/// Original retained coefficient owners are charged separately by that plan.
pub const CA_JOINT_WORKING_CAP_V1: usize = 640 << 20;

/// Reject overflow and excess actual capacity before the next working phase.
fn check_ca_working_payload_v1(parts: &[usize]) -> Result<usize, ZkX509CaAccumulatorProofErrorV1> {
    let total = parts
        .iter()
        .try_fold(0usize, |total, bytes| total.checked_add(*bytes))
        .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?;
    if total > CA_JOINT_WORKING_CAP_V1 {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    Ok(total)
}

/// Actual coefficient/LDE matrix allocation, including the outer header list.
fn ca_matrix_payload_v1<T>(
    columns: &[Vec<T>],
    capacity: usize,
) -> Result<usize, ZkX509CaAccumulatorProofErrorV1> {
    if capacity < columns.len() {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    let lists = capacity
        .checked_mul(core::mem::size_of::<Vec<T>>())
        .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?;
    columns.iter().try_fold(lists, |sum, column| {
        column
            .capacity()
            .checked_mul(core::mem::size_of::<T>())
            .and_then(|bytes| sum.checked_add(bytes))
            .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)
    })
}
