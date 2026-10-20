//! Consuming CA phases for the paired original-oracle proof.
//!
//! The local1363 AIR relation is completed by MAIN108 original-polynomial
//! cross equations. Neither component has an independent acceptance path.

use super::*;
use crate::privacy_engines::transparent_stark::{
    PrivacyOuterMerkleTreeV1, goldilocks_fp4_evaluate_coset_v1,
};
use crate::privacy_engines::zk_x509::credential_joint::{
    JointAuxiliaryBindingV1, JointDeepBindingV1, JointOriginalOpeningsV1, JointPointV1,
    JointSubproofV1,
};

use super::super::private_links::CA_EXTRA_MIX_LABEL_V1;

/// The two committed CA oracles and their original coefficient owner. No point
/// can be chosen until the paired MAIN phase supplies its own oracle checkpoint.
pub struct CaAwaitingJointPointV1 {
    original: CaAwaitingMainAuxiliaryV1,
    plan: CaMainPrivateLinkPlanV1,
    transcript: TransparentTranscriptV1,
    compositions: CaCompositionLanesV1,
    composition_trees: Vec<PrivacyOuterMerkleTreeV1>,
    fri_masks: Vec<aggregate::AggregateFriMaskOracleMaterialV1>,
}

/// Both normal DEEP and108 original auxiliary openings have been absorbed.
/// Independent batching coefficients require the paired opening capability.
pub struct CaAwaitingJointOpeningsV1 {
    oracles: CaAwaitingJointPointV1,
    point: E,
    deep: aggregate::AggregateDeepProofV1,
    extra_values: [E; CA_EXTRA_OPENINGS_V1],
}

impl CaAwaitingMainAuxiliaryV1 {
    /// Commit the local1363 relation after both original auxiliary roots.
    pub(crate) fn commit_joint_oracles_v1<R: TryRngCore>(
        self,
        auxiliary: JointAuxiliaryBindingV1,
        rng: &mut R,
    ) -> Result<CaAwaitingJointPointV1, ZkX509CaAccumulatorProofErrorV1> {
        let proof_instance = self.binding.proof_instance_v1();
        self.validate_v1()?;
        if !auxiliary.matches_v1(&self.binding, JointSubproofV1::Ca, self.auxiliary_root_v1()) {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        let layout = ca_aggregate_layout_v1()?;
        let plan = CaMainPrivateLinkPlanV1::new_v1(&self.schedule, self.binding.sha())?;
        let mut transcript = self.transcript;
        auxiliary
            .absorb_v1(&mut transcript)
            .map_err(map_transparent_proof_error_v1)?;
        plan.absorb_registration_v1(&mut transcript)?;
        let alphas = derive_ca_constraint_alphas_v1(&mut transcript)?;
        let compositions = self.local_composition_v1(&alphas, rng)?;
        let tree =
            aggregate::composition_tree_v1(&ca_domains_v1(proof_instance), 0, &compositions[0])
                .map_err(map_aggregate_proof_error_v1)?;
        aggregate::absorb_composition_roots_v1(
            &mut transcript,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &[tree.root()],
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let fri_masks = aggregate::build_fri_mask_oracles_v1(
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &layout,
            rng,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        if compositions.len() != 1 || fri_masks.len() != 1 {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        aggregate::absorb_fri_mask_roots_v1(
            &mut transcript,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &[fri_masks[0].tree.root()],
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let result = CaAwaitingJointPointV1 {
            original: self,
            plan,
            transcript,
            compositions,
            composition_trees: vec![tree],
            fri_masks,
        };
        result.check_working_payload_v1(&[])?;
        Ok(result)
    }
}
impl CaAwaitingJointPointV1 {
    /// Check actual retained compositions, masks and full tree allocations.
    /// The complete original coefficient owner is counted by the outer MAIN
    /// plan. Reserve bounded DEEP, query and codec material throughout instead
    /// of treating proof construction as free while private owners remain live.
    fn check_working_payload_v1(
        &self,
        extra: &[usize],
    ) -> Result<usize, ZkX509CaAccumulatorProofErrorV1> {
        let mut parts = vec![
            core::mem::size_of::<Self>(),
            self.compositions.capacity() * core::mem::size_of::<Vec<Vec<E>>>(),
            self.composition_trees.capacity() * core::mem::size_of::<PrivacyOuterMerkleTreeV1>(),
            self.fri_masks.capacity()
                * core::mem::size_of::<aggregate::AggregateFriMaskOracleMaterialV1>(),
            2 * ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 + (1 << 20),
        ];
        for lane in self.compositions.iter() {
            parts.push(ca_matrix_payload_v1(lane, lane.capacity())?);
        }
        for tree in &self.composition_trees {
            parts.push(
                tree.allocated_payload_bytes_v1()
                    .map_err(map_transparent_proof_error_v1)?,
            );
        }
        for mask in &self.fri_masks {
            parts.push(
                mask.evaluations
                    .capacity()
                    .checked_mul(core::mem::size_of::<E>())
                    .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?,
            );
            parts.push(
                mask.tree
                    .allocated_payload_bytes_v1()
                    .map_err(map_transparent_proof_error_v1)?,
            );
        }
        parts.extend_from_slice(extra);
        check_ca_working_payload_v1(&parts)
    }

    /// Exact local checkpoint and the original composition/mask roots, in order.
    pub(crate) fn checkpoint_v1(&self) -> [PrivacyOuterDigestV1; 3] {
        [
            self.transcript.state(),
            self.composition_trees[0].root(),
            self.fri_masks[0].tree.root(),
        ]
    }

    /// Direct Horner openings use only the original coefficients. Replaying
    /// trace commitments is deferred until the local FRI/query phase.
    pub(crate) fn open_joint_point_v1(
        mut self,
        point: JointPointV1,
    ) -> Result<CaAwaitingJointOpeningsV1, ZkX509CaAccumulatorProofErrorV1> {
        let z = point.point_v1();
        self.original.validate_link_plan_v1(&self.plan, z)?;
        point
            .absorb_v1(JointSubproofV1::Ca, &mut self.transcript)
            .map_err(map_transparent_proof_error_v1)?;
        let layout = ca_aggregate_layout_v1()?;
        let next = z.mul_base(
            goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1)
                .map_err(map_transparent_proof_error_v1)?,
        );
        let open = |owner: &CaOriginalMaskedColumnsV1,
                    target: E|
         -> Result<Vec<[u64; 4]>, ZkX509CaAccumulatorProofErrorV1> {
            let width = owner.family_v1().width_v1();
            let mut result = Vec::new();
            result
                .try_reserve_exact(width)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
            if result.capacity() != width {
                return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
            }
            for column in 0..width {
                result.push(owner.open_v1(column, target)?.coefficients().map(F::value));
            }
            Ok(result)
        };
        let trace = aggregate::AggregateDeepTraceGroupOpeningV1 {
            base_current: open(&self.original.base, z)?,
            base_next: open(&self.original.base, next)?,
            aux_current: open(&self.original.auxiliary, z)?,
            aux_next: open(&self.original.auxiliary, next)?,
        };
        let composition_values = aggregate::evaluate_composition_chunks_at_deep_v1(
            &self.compositions,
            CA_AGGREGATE_PARAMETERS_V1,
            &layout,
            z,
        )
        .map_err(map_aggregate_proof_error_v1)?
        .into_iter()
        .map(|lane| {
            lane.into_iter()
                .map(|value| value.coefficients().map(F::value))
                .collect()
        })
        .collect();
        let deep = aggregate::AggregateDeepProofV1 {
            trace_groups: vec![trace],
            composition_values,
        };
        aggregate::absorb_deep_openings_v1(
            &mut self.transcript,
            &deep,
            CA_AGGREGATE_PARAMETERS_V1,
            &layout,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let extra_values = self.original.open_link_values_v1(&self.plan, z)?;
        Ok(CaAwaitingJointOpeningsV1 {
            oracles: self,
            point: z,
            deep,
            extra_values,
        })
    }
}
impl CaAwaitingJointOpeningsV1 {
    /// This is the sole transition allowing either proof to sample DEEP mixes.
    /// MAIN must already have absorbed its normal DEEP and31 key openings.
    pub(crate) fn bind_with_main_v1(
        &mut self,
        main_transcript: &mut TransparentTranscriptV1,
        main_values: [E; 24],
    ) -> Result<JointDeepBindingV1, ZkX509CaAccumulatorProofErrorV1> {
        let proof_instance = self.oracles.original.binding.proof_instance_v1();
        JointOriginalOpeningsV1 {
            main: main_values,
            ca: self.extra_values,
        }
        .bind_both_v1(
            proof_instance,
            main_transcript,
            &mut self.oracles.transcript,
        )
        .map_err(map_transparent_proof_error_v1)
    }

    /// Finalize the original CA FRI with all108 supplemental divided differences.
    /// The caller still must verify the completed MAIN+CA credential together.
    pub(crate) fn finish_v1(
        mut self,
        binding: JointDeepBindingV1,
    ) -> Result<Vec<u8>, ZkX509CaAccumulatorProofErrorV1> {
        let proof_instance = self.oracles.original.binding.proof_instance_v1();
        if !binding.matches_v1(JointSubproofV1::Ca, &self.oracles.transcript)
            || binding.openings_v1().ca != self.extra_values
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch);
        }
        let layout = ca_aggregate_layout_v1()?;
        let deep_mixes = derive_ca_deep_mixes_v1(&mut self.oracles.transcript, &layout)?;
        let extra_mixes = ca_challenge_vector_v1(
            &mut self.oracles.transcript,
            CA_EXTRA_MIX_LABEL_V1,
            CA_EXTRA_OPENINGS_V1,
        )?;
        // Every synthetic remainder is checked before any original coefficient
        // owner is released or a supplemental quotient reaches the FRI.
        let extra_coefficients = self.oracles.original.link_deep_coefficients_v1(
            &self.oracles.plan,
            self.point,
            &self.extra_values,
            &extra_mixes,
        )?;
        let extra_lde = PrivateTableV1::new(
            goldilocks_fp4_evaluate_coset_v1(
                &extra_coefficients,
                layout.common_lde_size(),
                goldilocks_primitive_root_v1(layout.common_lde_log2())
                    .map_err(map_transparent_proof_error_v1)?,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_proof_error_v1)?,
            |values: &mut [E]| {
                super::super::super::private_table::zeroize_words_v1(values);
            },
        );
        drop(extra_coefficients);
        let base = self.oracles.original.base.local_lde_v1()?;
        let aux = self.oracles.original.auxiliary.local_lde_v1()?;
        let base_tree = aggregate::row_tree_v1(
            ca_domains_v1(proof_instance).digest_context,
            CA_BASE_LEAF_DOMAIN_V1,
            CA_BASE_NODE_DOMAIN_V1,
            0,
            &base,
            layout.common_lde_size(),
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let aux_tree = aggregate::row_tree_v1(
            ca_domains_v1(proof_instance).digest_context,
            CA_AUX_LEAF_DOMAIN_V1,
            CA_AUX_NODE_DOMAIN_V1,
            0,
            &aux,
            layout.common_lde_size(),
        )
        .map_err(map_aggregate_proof_error_v1)?;
        if base_tree.root() != self.oracles.original.trace_roots[0].base_root
            || aux_tree.root() != self.oracles.original.trace_roots[0].aux_root
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::TraceOpening);
        }
        // Both original commitment roots match before transferring the matrices.
        let trace_materials = vec![aggregate::AggregateTraceGroupMaterialV1 {
            base_lde: base.into_vec(),
            aux_lde: aux.into_vec(),
            base_tree,
            aux_tree,
        }];
        let trace = &trace_materials[0];
        let trace_work = [
            trace_materials.capacity()
                * core::mem::size_of::<aggregate::AggregateTraceGroupMaterialV1>(),
            ca_matrix_payload_v1(&trace.base_lde, trace.base_lde.capacity())?,
            ca_matrix_payload_v1(&trace.aux_lde, trace.aux_lde.capacity())?,
            trace
                .base_tree
                .allocated_payload_bytes_v1()
                .map_err(map_transparent_proof_error_v1)?,
            trace
                .aux_tree
                .allocated_payload_bytes_v1()
                .map_err(map_transparent_proof_error_v1)?,
        ];
        self.oracles.check_working_payload_v1(&[
            check_ca_working_payload_v1(&trace_work)?,
            extra_lde.capacity() * core::mem::size_of::<E>(),
            layout.common_lde_size() * core::mem::size_of::<E>(),
        ])?;
        let mut fri_base = PrivateTableV1::new(
            ca_fri_base_v1(
                &trace_materials[0],
                &self.oracles.compositions[0],
                &self.deep,
                self.point,
                &deep_mixes[0],
                &layout,
            )?,
            |values: &mut [E]| {
                super::super::super::private_table::zeroize_words_v1(values);
            },
        );
        let fri_rows = fri_base.len();
        let extra_rows = extra_lde.len();
        let expected_rows = layout.common_lde_size();
        if fri_rows != extra_rows
            || fri_base.capacity() != expected_rows
            || extra_lde.capacity() != expected_rows
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        for (target, extra) in fri_base.iter_mut().zip(extra_lde.iter()) {
            *target = target.add(*extra);
        }
        drop(extra_lde);
        aggregate::add_fri_mask_oracle_v1(&mut fri_base, &self.oracles.fri_masks[0])
            .map_err(map_aggregate_proof_error_v1)?;
        let fri = aggregate::build_fri_lane_v1(
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &layout,
            0,
            fri_base.into_vec(),
            &mut self.oracles.transcript,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let fri_materials = vec![fri];
        let mut fri_work = vec![
            check_ca_working_payload_v1(&trace_work)?,
            fri_materials.capacity()
                * core::mem::size_of::<aggregate::AggregateFriLaneMaterialV1>(),
        ];
        for lane in &fri_materials {
            fri_work.push(ca_matrix_payload_v1(&lane.layers, lane.layers.capacity())?);
            fri_work.push(lane.trees.capacity() * core::mem::size_of::<PrivacyOuterMerkleTreeV1>());
            fri_work.push(lane.roots.capacity() * core::mem::size_of::<PrivacyOuterDigestV1>());
            fri_work.push(lane.terminal_values.capacity() * core::mem::size_of::<E>());
            for tree in &lane.trees {
                fri_work.push(
                    tree.allocated_payload_bytes_v1()
                        .map_err(map_transparent_proof_error_v1)?,
                );
            }
        }
        self.oracles.check_working_payload_v1(&fri_work)?;
        let grinding_nonce = grind_nonce_v1(
            proof_instance.ca_context_v1(),
            &self.oracles.transcript.state(),
            ZK_X509_GRINDING_BITS_V1,
        )
        .map_err(map_transparent_proof_error_v1)?;
        absorb_ca_grinding_nonce_v1(&mut self.oracles.transcript, grinding_nonce)?;
        let indices = aggregate::query_indices_v1(
            &self.oracles.transcript,
            CA_AGGREGATE_PARAMETERS_V1,
            &ca_domains_v1(proof_instance),
            &layout,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        let queries = indices
            .iter()
            .copied()
            .map(|index| {
                aggregate::build_query_v1(
                    CA_AGGREGATE_PARAMETERS_V1,
                    &layout,
                    index,
                    &trace_materials,
                    &self.oracles.compositions,
                    &self.oracles.fri_masks,
                    &fri_materials,
                )
                .map_err(map_aggregate_proof_error_v1)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (trace_frontiers, composition_frontiers, fri_mask_frontiers, fri_round_frontiers) =
            aggregate::build_all_frontiers_v1(
                CA_AGGREGATE_PARAMETERS_V1,
                &layout,
                &queries,
                &trace_materials,
                &self.oracles.composition_trees,
                &self.oracles.fri_masks,
                &fri_materials,
            )
            .map_err(map_aggregate_proof_error_v1)?;
        let mut trace_groups = self.oracles.original.trace_roots.to_vec();
        for (group, (base_frontier, aux_frontier)) in trace_groups.iter_mut().zip(trace_frontiers) {
            group.base_frontier = base_frontier;
            group.aux_frontier = aux_frontier;
        }
        let proof = aggregate::AggregateStarkProofV1 {
            version: ZK_X509_PROOF_VERSION_V1,
            trace_groups,
            composition_roots: vec![self.oracles.composition_trees[0].root()],
            composition_frontiers,
            fri_mask_roots: vec![self.oracles.fri_masks[0].tree.root()],
            fri_mask_frontiers,
            fri_lanes: fri_materials
                .into_iter()
                .zip(fri_round_frontiers)
                .map(
                    |(lane, round_frontiers)| aggregate::AggregateFriLaneProofV1 {
                        roots: lane.roots,
                        terminal_values: lane
                            .terminal_values
                            .into_iter()
                            .map(|value| value.coefficients().map(F::value))
                            .collect(),
                        round_frontiers,
                    },
                )
                .collect(),
            queries,
            grinding_nonce,
        };
        let inner = aggregate::encode_proof_with_deep_v1(
            &proof,
            &self.deep,
            CA_AGGREGATE_PARAMETERS_V1,
            &layout,
        )
        .map_err(map_aggregate_proof_error_v1)?;
        encode_ca_proof_envelope_v1(&inner)
    }
}

#[cfg(test)]
#[path = "accumulator_joint_prover_tests.rs"]
pub mod tests;
