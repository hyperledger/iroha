//! Unconditional SHA digest-word joins to the unreduced real P256 byte inputs.
//!
//! One fixed SHA row holds a u32 while four P256 rows hold its big-endian bytes.
//! The power32 map advances four native-log16 rows per native-log19 SHA row.
//! Optional certificate digest rows remain real SHA(empty) computations; no
//! private activity factor may disable these equalities.

use super::*;
use crate::privacy_engines::zk_x509::{
    p256_aggregate_adapter::p256_real_digest_input_columns_v1,
    sha_call_bus_stark::{
        ZK_X509_SHA_SEGMENT_ROWS_V1, ZkX509ShaCallActivationV1, ZkX509ShaCallPublicShapeV1,
        ZkX509ShaCallRoleV1, ZkX509ShaCallScheduleV1,
    },
};

pub(super) const DIGEST_BLOCKS_V1: usize = 5;
pub(super) const DIGEST_OPENINGS_V1: usize = 4 * DIGEST_BLOCKS_V1;
const CALLS_V1: [usize; DIGEST_BLOCKS_V1] = [0, 1, 2, 3, 11];
const WEIGHTS_V1: [F; 4] = [F(1 << 24), F(1 << 16), F(1 << 8), F::ONE];
const DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:main-sha-p256-digest-joins:v1";
const DIGEST_DESCRIPTOR_V1: &[u8] = b"5-signatures:sha-calls0,1,2,3,11:word-column0:fixed-final-eight-digest-rows:real-p256-column-before-selection:bytes128..160:8-u32-per-call=4-big-endian-u8:weights16777216,65536,256,1:root-power32:all-five-unconditional-including-sha-empty-dummy:unreduced-digest-before-p256-reduction:20-original-column-DEEP-openings";

/// The closed call schedule, fixed columns and native roots determine every cell.
#[derive(Clone, Copy)]
pub(super) struct MainDigestJoinPlanV1 {
    blocks: [BlockV1; DIGEST_BLOCKS_V1],
    byte_step: F,
}

impl MainDigestJoinPlanV1 {
    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        disclosures: usize,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: disclosures,
        })
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let source_root = goldilocks_primitive_root_v1(19).map_err(map_transparent_error_v1)?;
        let target_root = goldilocks_primitive_root_v1(16).map_err(map_transparent_error_v1)?;
        if source_root.pow(32) != target_root.pow(4) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let (target_local_column, target_start) = p256_real_digest_input_columns_v1();
        if target_start.checked_add(32).is_none_or(|end| end > 1 << 16) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let column = |registration: RegisteredSegmentLayoutV1, local: usize| {
            if local >= registration.segment.base_width {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok(ColumnV1 {
                group: registration.trace_group,
                column: registration
                    .base_start
                    .checked_add(local)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                log: registration.segment.trace_log2,
            })
        };
        let dummy_column = ColumnV1 {
            group: 0,
            column: 0,
            log: 19,
        };
        let mut blocks = [BlockV1 {
            source: dummy_column,
            target: dummy_column,
            start: F::ONE,
            step: source_root,
            count: 8,
            power: 32,
            scale: F::ONE,
        }; DIGEST_BLOCKS_V1];
        for (signature, call_index) in CALLS_V1.into_iter().enumerate() {
            let manifest = *schedule
                .calls()
                .get(call_index)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            let expected_role = match signature {
                0..=2 => ZkX509ShaCallRoleV1::CertificateTbs(signature as u8),
                3 => ZkX509ShaCallRoleV1::CrlTbs,
                _ => ZkX509ShaCallRoleV1::Projection(6),
            };
            let expected_activation = if signature == 2 {
                ZkX509ShaCallActivationV1::OptionalPrivate
            } else {
                ZkX509ShaCallActivationV1::Required
            };
            if usize::from(manifest.call) != call_index
                || manifest.role != expected_role
                || manifest.activation != expected_activation
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let segment = manifest.first_logical_row / ZK_X509_SHA_SEGMENT_ROWS_V1;
            let first = manifest.first_logical_row % ZK_X509_SHA_SEGMENT_ROWS_V1;
            let digest_row = manifest
                .maximum_local_rows
                .checked_sub(8)
                .and_then(|row| first.checked_add(row))
                .filter(|row| {
                    row.checked_add(8)
                        .is_some_and(|end| end <= ZK_X509_SHA_SEGMENT_ROWS_V1)
                })
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            let sha = layout.registered_segment(
                SegmentAdapterIdV1::Sha256CallBus,
                u16::try_from(segment).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
            )?;
            let identity =
                P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::BindingSink, 0)?;
            let mut sinks =
                layout.registered_segments.iter().copied().filter(|r| {
                    p256_main_registration_from_main_layout_v1(*r).ok() == Some(identity)
                });
            let sink = sinks.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            if sinks.next().is_some()
                || sha.segment.trace_log2 != 19
                || sink.segment.trace_log2 != 16
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let start = source_root.pow(digest_row as u128);
            blocks[signature] = BlockV1 {
                source: column(sha, 0)?,
                target: column(sink, target_local_column)?,
                start,
                step: source_root,
                count: 8,
                power: 32,
                scale: target_root.pow(target_start as u128).mul(
                    start
                        .pow(32)
                        .inv()
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                ),
            };
        }
        let shared = layout.as_shared()?;
        let chunks =
            crate::privacy_engines::zk_x509::composition_masking::QuotientChunkGeometryV1::new_v1(
                &shared,
                AGGREGATE_PARAMETERS_V1,
            )
            .map_err(map_aggregate_error_v1)?;
        let degree = 32 * ((1_usize << 16) + MASK_DEGREE) - 8;
        if chunks
            .stride_v1()
            .checked_mul(AGGREGATE_PARAMETERS_V1.composition_degree_chunks)
            .is_none_or(|covered| degree >= covered)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(Self {
            blocks,
            byte_step: target_root,
        })
    }

    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(super) fn source_v1(&self, signature: usize) -> Result<ColumnV1, ZkX509StarkErrorV1> {
        self.blocks
            .get(signature)
            .map(|b| b.source)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(super) fn target_v1(&self, signature: usize) -> Result<ColumnV1, ZkX509StarkErrorV1> {
        self.blocks
            .get(signature)
            .map(|b| b.target)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    pub(super) fn opening_v1(
        &self,
        index: usize,
        z: E,
    ) -> Result<(ColumnV1, E), ZkX509StarkErrorV1> {
        let b = *self
            .blocks
            .get(index / 4)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Ok((
            b.target,
            MainKeyJoinPlanV1::target_point_v1(b, z)
                .mul_base(self.byte_step.pow((index % 4) as u128)),
        ))
    }
    pub(super) fn absorb_plan_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        transcript
            .absorb(DIGEST_DOMAIN_V1, &[DIGEST_DESCRIPTOR_V1])
            .map_err(map_transparent_error_v1)?;
        for b in self.blocks {
            let mut record = [0_u8; 107];
            for (i, v) in [
                b.source.group,
                b.source.column,
                b.target.group,
                b.target.column,
                b.count,
            ]
            .into_iter()
            .enumerate()
            {
                record[8 * i..8 * i + 8].copy_from_slice(&(v as u64).to_be_bytes());
            }
            record[40..48].copy_from_slice(&b.start.0.to_be_bytes());
            record[48..56].copy_from_slice(&b.step.0.to_be_bytes());
            record[56..64].copy_from_slice(&b.scale.0.to_be_bytes());
            record[64] = b.source.log;
            record[65] = b.target.log;
            record[66] = b.power;
            record[67..75].copy_from_slice(&self.byte_step.0.to_be_bytes());
            for (i, w) in WEIGHTS_V1.into_iter().enumerate() {
                record[75 + 8 * i..83 + 8 * i].copy_from_slice(&w.0.to_be_bytes());
            }
            transcript
                .absorb(DIGEST_DOMAIN_V1, &[&record])
                .map_err(map_transparent_error_v1)?;
        }
        Ok(())
    }
    pub(super) fn evaluate_v1(
        &self,
        groups: &[aggregate::AggregateOpenedDeepTraceGroupV1],
        z: E,
        values: &[E],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if values.len() != DIGEST_OPENINGS_V1
            || alphas.len() != DIGEST_BLOCKS_V1
            || values.iter().chain(alphas).any(|x| !x.is_canonical())
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        let mut sum = E::ZERO;
        for (signature, b) in self.blocks.iter().enumerate() {
            let word = groups
                .get(b.source.group)
                .and_then(|g| g.base_current.get(b.source.column))
                .copied()
                .ok_or(ZkX509StarkErrorV1::ConstraintOpening)?;
            let bytes = (0..4).fold(E::ZERO, |v, j| {
                v.add(values[4 * signature + j].mul_base(WEIGHTS_V1[j]))
            });
            let mut point = b.start;
            let mut divisor = E::ONE;
            for _ in 0..8 {
                divisor = divisor.mul(z.sub(E::from_base(point)));
                point = point.mul(b.step);
            }
            sum = sum.add(
                alphas[signature]
                    .mul(word.sub(bytes))
                    .mul(divisor.inv().ok_or(ZkX509StarkErrorV1::ConstraintOpening)?),
            );
        }
        Ok(sum)
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainDigestJoinPlanV1 {
    fn weighted_coefficients_v1(
        &self,
        target: &[F],
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if target.is_empty() || target.iter().any(|v| F::canonical(v.0).is_none()) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut weighted = ZeroizingMainTraceColumnV1(Vec::new());
        weighted
            .0
            .try_reserve_exact(target.len())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if weighted.0.capacity() != target.len() {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        let mut powers = [F::ONE; 4];
        let steps = core::array::from_fn::<_, 4, _>(|j| self.byte_step.pow(j as u128));
        for coefficient in target {
            let factor = (0..4).fold(F::ZERO, |v, j| v.add(WEIGHTS_V1[j].mul(powers[j])));
            weighted.0.push(coefficient.mul(factor));
            for j in 0..4 {
                powers[j] = powers[j].mul(steps[j]);
            }
        }
        Ok(weighted)
    }
    pub(super) fn quotient_v1(
        &self,
        signature: usize,
        source: &[F],
        target: &[F],
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let block = *self
            .blocks
            .get(signature)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let weighted = self.weighted_coefficients_v1(target)?;
        MainKeyJoinPlanV1::quotient_v1(block, source, &weighted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        p256_external_binding_air::{
            P256_INPUT_SELECTION_ROW_START_V1, ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
        },
        sha_call_bus_stark::{
            ZkX509ShaBatchFixedProviderV1, ZkX509ShaCallWitnessV1,
            build_zk_x509_sha_batch_call_base_source_v1,
        },
        sha_word_stark::{
            SHA_WORD_CAPACITY_DIGEST_SELECTOR_V1, SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1,
        },
    };
    use sha2::{Digest as _, Sha256};

    fn plan_v1(disclosures: usize) -> MainDigestJoinPlanV1 {
        MainDigestJoinPlanV1::new_v1(
            &AggregateProofLayoutV1::for_full_profile_v1().unwrap(),
            disclosures,
        )
        .unwrap()
    }
    fn polynomial_v1(points: &[F], values: &[F]) -> Vec<F> {
        let mut out = vec![F::ZERO; points.len()];
        for (i, point) in points.iter().enumerate() {
            let mut basis = vec![F::ONE];
            let mut denominator = F::ONE;
            for (j, other) in points.iter().enumerate() {
                if i == j {
                    continue;
                }
                denominator = denominator.mul(point.sub(*other));
                let mut next = vec![F::ZERO; basis.len() + 1];
                for (k, v) in basis.iter().enumerate() {
                    next[k] = next[k].sub(v.mul(*other));
                    next[k + 1] = next[k + 1].add(*v);
                }
                basis = next;
            }
            let scale = values[i].mul(denominator.inv().unwrap());
            for (k, v) in basis.iter().enumerate() {
                out[k] = out[k].add(v.mul(scale));
            }
        }
        out
    }
    fn byte_case_v1(
        plan: &MainDigestJoinPlanV1,
        signature: usize,
        bytes: [u8; 32],
    ) -> (Vec<F>, Vec<F>) {
        let b = plan.blocks[signature];
        let source_points: Vec<_> = (0..8).map(|i| b.start.mul(b.step.pow(i))).collect();
        let target_points: Vec<_> = (0..32)
            .map(|i| b.scale.mul(b.start.pow(32)).mul(plan.byte_step.pow(i)))
            .collect();
        let words: Vec<_> = bytes
            .chunks_exact(4)
            .map(|word| F(u64::from(u32::from_be_bytes(word.try_into().unwrap()))))
            .collect();
        (
            polynomial_v1(&source_points, &words),
            polynomial_v1(&target_points, &bytes.map(|v| F(u64::from(v)))),
        )
    }

    #[test]
    fn digest_plan_matches_actual_fixed_sha_rows_and_real_unreduced_p256_owners() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let (column, start) = p256_real_digest_input_columns_v1();
        assert_eq!(column, 6);
        assert_eq!(start, P256_INPUT_SELECTION_ROW_START_V1 + 128);
        for disclosures in 0..=4 {
            let plan = plan_v1(disclosures);
            let fixed = ZkX509ShaBatchFixedProviderV1::new_v1(ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes: disclosures,
            })
            .unwrap();
            for (signature, (segment, row)) in [
                (1, 69168),
                (2, 69168),
                (2, 277_200),
                (3, 69168),
                (3, 348_784),
            ]
            .into_iter()
            .enumerate()
            {
                let b = plan.blocks[signature];
                let registration = layout
                    .registered_segment(SegmentAdapterIdV1::Sha256CallBus, segment)
                    .unwrap();
                assert_eq!(b.source.column, registration.base_start);
                assert_eq!(b.source.group, registration.trace_group);
                assert_eq!(
                    b.start,
                    goldilocks_primitive_root_v1(19).unwrap().pow(row as u128)
                );
                for word in 0..8 {
                    let f = fixed.fixed_row_v1(segment as usize, row + word).unwrap();
                    assert_eq!(f[SHA_WORD_CAPACITY_DIGEST_SELECTOR_V1], F::ONE);
                    assert_eq!(f[SHA_WORD_CAPACITY_DIGEST_WORD_INDEX_V1], F(word as u64));
                    for byte in 0..4 {
                        let (_, point) = plan
                            .opening_v1(
                                4 * signature + byte,
                                E::from_base(b.start.mul(b.step.pow(word as u128))),
                            )
                            .unwrap();
                        assert_eq!(
                            point,
                            E::from_base(plan.byte_step.pow((start + 4 * word + byte) as u128))
                        );
                    }
                }
            }
        }
        assert!(MainDigestJoinPlanV1::new_v1(&layout, 5).is_err());
        let plan = plan_v1(0);
        assert!(plan.source_v1(5).is_err());
        assert!(plan.target_v1(5).is_err());
        assert!(plan.opening_v1(20, E::ONE).is_err());
    }

    #[test]
    fn actual_sha_digest_words_join_every_byte_in_enabled_and_dummy_slots() {
        let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 0,
        })
        .unwrap();
        let plan = plan_v1(0);
        for (signature, call) in CALLS_V1.into_iter().enumerate() {
            for dummy in [false, true] {
                if dummy && signature != 2 {
                    continue;
                }
                let message = if dummy {
                    vec![]
                } else {
                    vec![signature as u8 + 19; 35 + signature]
                };
                let digest: [u8; 32] = Sha256::digest(&message).into();
                if dummy {
                    assert_eq!(digest, ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1);
                }
                let manifest = schedule.calls()[call];
                let witness = ZkX509ShaCallWitnessV1 {
                    role: manifest.role,
                    message,
                    digest,
                };
                let source =
                    build_zk_x509_sha_batch_call_base_source_v1(manifest, &witness, 0).unwrap();
                for word in 0..8 {
                    let row = source
                        .base_row(manifest.maximum_local_rows - 8 + word)
                        .unwrap();
                    assert_eq!(
                        row[0],
                        F(u64::from(u32::from_be_bytes(
                            digest[4 * word..4 * word + 4].try_into().unwrap()
                        )))
                    );
                }
                let (source_polynomial, target) = byte_case_v1(&plan, signature, digest);
                assert!(
                    plan.quotient_v1(signature, &source_polynomial, &target)
                        .is_ok()
                );
                for byte in 0..32 {
                    let mut changed = digest;
                    changed[byte] ^= 1;
                    let (_, changed_target) = byte_case_v1(&plan, signature, changed);
                    assert!(
                        plan.quotient_v1(signature, &source_polynomial, &changed_target)
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn digest_packing_rejects_endianness_reduction_wrong_map_and_every_opening_mutation() {
        let plan = plan_v1(4);
        let digest = core::array::from_fn(|i| 255 - i as u8);
        let (source, target) = byte_case_v1(&plan, 0, digest);
        let quotient = plan.quotient_v1(0, &source, &target).unwrap();
        let z = E::canonical([31, 5, 17, 2]).unwrap();
        let b = plan.blocks[0];
        let weighted = plan.weighted_coefficients_v1(&target).unwrap();
        let weighted_at = MainKeyJoinPlanV1::evaluate_coefficients_v1(
            &weighted,
            MainKeyJoinPlanV1::target_point_v1(b, z),
        );
        let direct = (0..4).fold(E::ZERO, |sum, j| {
            sum.add(
                MainKeyJoinPlanV1::evaluate_coefficients_v1(
                    &target,
                    plan.opening_v1(j, z).unwrap().1,
                )
                .mul_base(WEIGHTS_V1[j]),
            )
        });
        assert_eq!(weighted_at, direct);
        let denominator = (0..8).fold(E::ONE, |v, i| {
            v.mul(z.sub(E::from_base(b.start.mul(b.step.pow(i)))))
        });
        assert_eq!(
            MainKeyJoinPlanV1::evaluate_coefficients_v1(&quotient, z),
            MainKeyJoinPlanV1::evaluate_coefficients_v1(&source, z)
                .sub(direct)
                .mul(denominator.inv().unwrap())
        );
        let mut little = digest;
        for word in little.chunks_exact_mut(4) {
            word.reverse();
        }
        let (_, wrong) = byte_case_v1(&plan, 0, little);
        assert!(plan.quotient_v1(0, &source, &wrong).is_err());
        // All-ones is above the P256 scalar modulus. The source remains the raw
        // SHA integer; consuming the already-reduced value is a different relation.
        let raw = [255; 32];
        let (raw_source, _) = byte_case_v1(&plan, 0, raw);
        let modulus = crate::privacy_engines::zk_x509::p256_air::P256_SCALAR_MODULUS_BE_V1;
        let reduced = modulus.map(|b| 255 - b);
        let (_, wrong) = byte_case_v1(&plan, 0, reduced);
        assert!(plan.quotient_v1(0, &raw_source, &wrong).is_err());
        for variant in 0..4 {
            let mut changed = plan;
            match variant {
                0 => changed.blocks[0].power = 8,
                1 => changed.blocks[0].scale = changed.blocks[0].scale.mul(plan.byte_step),
                2 => changed.blocks[0].start = changed.blocks[0].start.mul(b.step),
                _ => changed.byte_step = changed.byte_step.inv().unwrap(),
            };
            assert!(changed.quotient_v1(0, &source, &target).is_err());
        }
        assert!(plan.weighted_coefficients_v1(&[]).is_err());
        assert!(plan.weighted_coefficients_v1(&[F(u64::MAX)]).is_err());
        assert!(plan.quotient_v1(5, &source, &target).is_err());
        assert!(plan.quotient_v1(0, &[F::ZERO; 8], &[F::ZERO; 32]).is_ok());
        let fresh = || {
            new_main_transcript_after_profile_validation_v1(
                TEST_PROOF_INSTANCE_V1,
                &[7; 32],
                [8; 32],
            )
            .unwrap()
        };
        let state = |p: MainDigestJoinPlanV1| {
            let mut t = fresh();
            p.absorb_plan_v1(&mut t).unwrap();
            t.state()
        };
        let expected = state(plan);
        for variant in 0..7 {
            let mut changed = plan;
            match variant {
                0 => changed.blocks.swap(0, 1),
                1 => changed.blocks[0].source.column += 1,
                2 => changed.blocks[0].target.column += 1,
                3 => changed.blocks[0].start = changed.blocks[0].start.mul(b.step),
                4 => changed.blocks[0].power = 8,
                5 => changed.blocks[0].scale = changed.blocks[0].scale.add(F::ONE),
                _ => changed.byte_step = F::ONE,
            };
            assert_ne!(state(changed), expected);
        }
    }
    #[test]
    fn weighted_fp4_verifier_equations_bind_each_digest_opening_and_owner() {
        let plan = plan_v1(4);
        let z = E::canonical([31, 5, 17, 2]).unwrap();
        let max_group = plan.blocks.iter().map(|b| b.source.group).max().unwrap();
        let max_column = plan.blocks.iter().map(|b| b.source.column).max().unwrap();
        let mut groups = (0..=max_group)
            .map(|_| aggregate::AggregateOpenedDeepTraceGroupV1 {
                base_current: vec![E::from_base(F(103)); max_column + 1],
                base_next: Vec::new(),
                aux_current: Vec::new(),
                aux_next: Vec::new(),
            })
            .collect::<Vec<_>>();
        let values = core::array::from_fn::<_, DIGEST_OPENINGS_V1, _>(|i| {
            E::canonical([i as u64 + 107, 3, 5, 7]).unwrap()
        });
        let alphas = [E::from_base(F(113)); DIGEST_BLOCKS_V1];
        let expected = plan.blocks.iter().enumerate().fold(E::ZERO, |sum, (i, b)| {
            let combined = values[4 * i]
                .mul_base(F(1 << 24))
                .add(values[4 * i + 1].mul_base(F(1 << 16)))
                .add(values[4 * i + 2].mul_base(F(1 << 8)))
                .add(values[4 * i + 3]);
            let divisor = (0..8).fold(E::ONE, |v, j| {
                v.mul(z.sub(E::from_base(b.start.mul(b.step.pow(j)))))
            });
            sum.add(
                E::from_base(F(103))
                    .sub(combined)
                    .mul(divisor.inv().unwrap())
                    .mul(alphas[i]),
            )
        });
        assert_eq!(
            plan.evaluate_v1(&groups, z, &values, &alphas).unwrap(),
            expected
        );
        for i in 0..DIGEST_OPENINGS_V1 {
            let mut changed = values;
            changed[i] = changed[i].add(E::ONE);
            assert_ne!(
                plan.evaluate_v1(&groups, z, &changed, &alphas).unwrap(),
                expected
            );
        }
        assert!(
            plan.evaluate_v1(&groups, z, &values[..19], &alphas)
                .is_err()
        );
        assert!(plan.evaluate_v1(&groups, z, &values, &alphas[..4]).is_err());
        assert!(plan.evaluate_v1(&[], z, &values, &alphas).is_err());
        let owner = plan.blocks[0].source;
        groups[owner.group].base_current[owner.column] = E::from_base(F(104));
        assert_ne!(
            plan.evaluate_v1(&groups, z, &values, &alphas).unwrap(),
            expected
        );
    }
}
