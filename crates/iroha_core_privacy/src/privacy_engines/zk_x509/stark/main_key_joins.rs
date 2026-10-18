//! Verifier-owned RFC key bytes joined to real P256 and `ByteMemory` columns.
//!
//! A native-root power map joins a complete consecutive byte block with one
//! quotient. Derived target evaluations are separately bound to the original
//! committed column by DEEP; this is not equality of independently masked traces.

use super::super::super::p256_aggregate_adapter::p256_real_key_input_columns_v1;
use super::super::super::rfc5280_stark::zk_x509_rfc_key_join_rows_v1;
use super::*;

const KEY_BLOCKS_V1: usize = 12;
const KEY_OPENINGS_V1: usize = 11;
#[path = "main_digest_joins.rs"]
mod main_digest_joins;
use main_digest_joins::{DIGEST_BLOCKS_V1, DIGEST_OPENINGS_V1, MainDigestJoinPlanV1};
pub(super) const BLOCKS_V1: usize = KEY_BLOCKS_V1 + DIGEST_BLOCKS_V1;
pub(in super::super) const OPENINGS_V1: usize = KEY_OPENINGS_V1 + DIGEST_OPENINGS_V1;
// The current first-release profile fixes eleven key and twenty digest DEEP values.
const _: () = assert!(OPENINGS_V1 == 31);
const DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:main-key-byte-joins:v1";
const DESCRIPTOR_V1: &[u8] = b"rfc-producer-to-io5x65+p256-real5x64:selector-io1+activity1:12-key-blocks647-equalities+5-sha-digest-blocks40-u32-equalities:root-power2,8,32:original-masks:31-extra-deep-openings:no-private-byte-divisions";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColumnV1 {
    group: usize,
    column: usize,
    log: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockV1 {
    source: ColumnV1,
    target: ColumnV1,
    start: F,
    step: F,
    count: usize,
    power: u8,
    scale: F,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::stark::tests::main_log19_statement_fixture_v1;

    fn plan_v1(disclosures: usize) -> (AggregateProofLayoutV1, MainKeyJoinPlanV1) {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let statement =
            crate::privacy_engines::zk_x509::main_io::tests::statement_with_disclosures_v1(
                disclosures,
            );
        let mut rfc_statement = main_log19_statement_fixture_v1();
        rfc_statement.disclosed_attribute_indices = (0..disclosures as u8).collect();
        let shape = ZkX509Rfc5280StarkShapeV1::from_statement(&rfc_statement).unwrap();
        let plan = MainKeyJoinPlanV1::new_v1(&layout, &statement, shape).unwrap();
        (layout, plan)
    }
    fn product_v1(a: &[F], b: &[F]) -> Vec<F> {
        let mut out = vec![F::ZERO; a.len() + b.len() - 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                out[i + j] = out[i + j].add(x.mul(*y));
            }
        }
        out
    }
    fn public_block_v1(power: u8, count: usize) -> (BlockV1, Vec<F>, Vec<F>, Vec<F>) {
        let column = ColumnV1 {
            group: 0,
            column: 0,
            log: 19,
        };
        let b = BlockV1 {
            source: column,
            target: column,
            start: F(11),
            step: goldilocks_primitive_root_v1(19).unwrap(),
            count,
            power,
            scale: F(13),
        };
        let target = vec![F(3), F(5), F(7), F(19)];
        let mut divisor = vec![F::ONE];
        let mut p = b.start;
        for _ in 0..count {
            divisor = product_v1(&divisor, &[F::ZERO.sub(p), F::ONE]);
            p = p.mul(b.step);
        }
        let q = vec![F(23), F(29)];
        let mut source = product_v1(&divisor, &q);
        source.resize(source.len().max(3 * power as usize + 1), F::ZERO);
        let mut cp = F::ONE;
        for (j, v) in target.iter().enumerate() {
            source[j * power as usize] = source[j * power as usize].add(v.mul(cp));
            cp = cp.mul(b.scale);
        }
        (b, source, target, q)
    }
    #[test]
    fn canonical_public_plan_covers_every_byte_and_both_selectors() {
        for d in 0..=4 {
            let (_, plan) = plan_v1(d);
            assert_eq!(plan.blocks.len(), 12);
            assert_eq!(plan.blocks.iter().map(|b| b.count).sum::<usize>(), 647);
            for b in plan.blocks {
                let target_root = goldilocks_primitive_root_v1(b.target.log).unwrap();
                assert_eq!(
                    b.step.pow(u128::from(b.power)),
                    if b.count == 1 && b.power == 1 {
                        F::ONE
                    } else {
                        target_root
                    }
                );
                let mut x = b.start;
                let first = b.scale.mul(x.pow(u128::from(b.power)));
                for j in 0..b.count {
                    assert_eq!(
                        b.scale.mul(x.pow(u128::from(b.power))),
                        first.mul(target_root.pow(j as u128))
                    );
                    x = x.mul(b.step);
                }
            }
        }
        let (_, plan) = plan_v1(0);
        assert_eq!(
            plan.blocks.map(|b| b.scale.0),
            [
                7_017_390_190_810_289_357,
                17_503_853_696_544_898_926,
                9_865_662_462_788_700_761,
                9_722_880_242_497_423_035,
                2_494_635_378_086_535_074,
                9_417_717_310_630_869_886,
                9_606_226_123_056_290_305,
                16_567_939_589_808_255_578,
                2_572_097_256_420_412_601,
                3_184_775_124_554_532_950,
                12_196_860_509_838_602_653,
                1
            ]
        );
    }
    #[test]
    fn exact_division_preserves_zero_bytes_and_detects_each_endpoint_mutation() {
        for (power, count) in [(1, 1), (2, 65), (8, 64)] {
            let (b, source, target, q) = public_block_v1(power, count);
            let quotient = MainKeyJoinPlanV1::quotient_v1(b, &source, &target).unwrap();
            assert_eq!(&quotient[..q.len()], q.as_slice());
            assert!(quotient[q.len()..].iter().all(|x| *x == F::ZERO));
            assert!(
                MainKeyJoinPlanV1::quotient_v1(
                    b,
                    &vec![F::ZERO; source.len()],
                    &vec![F::ZERO; target.len()]
                )
                .unwrap()
                .iter()
                .all(|x| *x == F::ZERO)
            );
            let mut points = Vec::new();
            let mut point = b.start;
            for _ in 0..count {
                points.push(point);
                point = point.mul(b.step);
            }
            for changed in 0..count {
                let mut delta = vec![F::ONE];
                for (i, p) in points.iter().enumerate() {
                    if i != changed {
                        delta = product_v1(&delta, &[F::ZERO.sub(*p), F::ONE]);
                    }
                }
                let mut mutant = source.clone();
                for (i, v) in delta.iter().enumerate() {
                    mutant[i] = mutant[i].add(*v);
                }
                assert!(MainKeyJoinPlanV1::quotient_v1(b, &mutant, &target).is_err());
            }
        }
    }
    #[test]
    fn arbitrary_fp4_lifting_matches_exact_coefficient_quotient() {
        for (power, count) in [(1, 1), (2, 65), (8, 64)] {
            let (b, source, target, q) = public_block_v1(power, count);
            for z in [E::from_base(F(31)), E::canonical([31, 5, 17, 2]).unwrap()] {
                let mut p = b.start;
                let mut v = E::ONE;
                for _ in 0..count {
                    v = v.mul(z.sub(E::from_base(p)));
                    p = p.mul(b.step);
                }
                let lhs = MainKeyJoinPlanV1::evaluate_coefficients_v1(&source, z)
                    .sub(MainKeyJoinPlanV1::evaluate_coefficients_v1(
                        &target,
                        MainKeyJoinPlanV1::target_point_v1(b, z),
                    ))
                    .mul(v.inv().unwrap());
                assert_eq!(lhs, MainKeyJoinPlanV1::evaluate_coefficients_v1(&q, z));
            }
        }
    }
    #[test]
    fn point_admission_and_supplemental_ownership_are_exact() {
        let (layout, plan) = plan_v1(0);
        let shared = layout.as_shared().unwrap();
        for bad in [
            E::ZERO,
            E::ONE,
            E::from_base(F(7)),
            E::from_base(goldilocks_primitive_root_v1(19).unwrap()),
        ] {
            assert!(!plan.admissible_v1(bad, &shared).unwrap());
        }
        let z = E::canonical([31, 5, 17, 2]).unwrap();
        assert!(plan.admissible_v1(z, &shared).unwrap());
        let values = [E::from_base(F(43)); OPENINGS_V1];
        let mixes = [E::from_base(F(47)); OPENINGS_V1];
        let extras = plan.supplemental_v1(z, &values, &mixes).unwrap();
        assert_eq!(extras.capacity(), OPENINGS_V1);
        for (i, e) in extras.iter().enumerate() {
            let (column, point) = plan.opening_v1(i, z).unwrap();
            assert_eq!(e.group, column.group);
            assert_eq!(
                e.column,
                aggregate::AggregateSupplementalColumnV1::Base(column.column)
            );
            assert_eq!(e.point, point);
            assert_eq!(e.value, values[i]);
            assert_eq!(e.mix, mixes[i]);
        }
        assert!(plan.supplemental_v1(z, &values, &mixes[..10]).is_err());
    }
    #[test]
    fn plan_and_all_openings_are_transcript_bound_before_mixing() {
        let (_, plan) = plan_v1(0);
        let fresh = || {
            new_main_transcript_after_profile_validation_v1(
                TEST_PROOF_INSTANCE_V1,
                &[7; 32],
                [8; 32],
            )
            .unwrap()
        };
        let expected = plan.derive_alphas_v1(&mut fresh()).unwrap();
        assert_eq!(expected.len(), BLOCKS_V1);
        assert_eq!(expected.capacity(), BLOCKS_V1);
        for variant in 0..9 {
            let (_, mut changed) = plan_v1(0);
            match variant {
                0 => changed.blocks.swap(0, 1),
                1 => changed.blocks[0].source.column += 1,
                2 => changed.blocks[0].target.column += 1,
                3 => changed.blocks[0].count -= 1,
                4 => changed.blocks[0].start = changed.blocks[0].start.add(F::ONE),
                5 => changed.blocks[0].step = changed.blocks[0].step.add(F::ONE),
                6 => changed.blocks[0].scale = changed.blocks[0].scale.add(F::ONE),
                7 => changed.blocks[0].power = 8,
                _ => changed.blocks[0].target.log -= 1,
            }
            assert_ne!(changed.derive_alphas_v1(&mut fresh()).unwrap(), expected);
        }
        let base_values = [E::from_base(F(43)); OPENINGS_V1];
        let derive = |values: &[E; OPENINGS_V1]| {
            let mut transcript = fresh();
            MainKeyJoinPlanV1::absorb_openings_v1(values, &mut transcript).unwrap();
            MainKeyJoinPlanV1::derive_mixes_v1(&mut transcript).unwrap()
        };
        let expected = derive(&base_values);
        assert_eq!(expected.capacity(), OPENINGS_V1);
        for i in 0..OPENINGS_V1 {
            for limb in 0..4 {
                let mut changed = base_values;
                let mut words = changed[i].coefficients().map(F::value);
                words[limb] += 1;
                changed[i] = E::canonical(words).unwrap();
                assert_ne!(derive(&changed), expected);
            }
        }
        let mut actual = fresh();
        let mut serial = actual;
        let actual_values =
            MainKeyJoinPlanV1::exact_challenges_v1(&mut actual, DOMAIN_V1, BLOCKS_V1).unwrap();
        let serial_values: Vec<_> = (0..BLOCKS_V1)
            .map(|_| serial.challenge_fp4(DOMAIN_V1).unwrap())
            .collect();
        assert_eq!(actual_values, serial_values);
        assert_eq!(actual.state(), serial.state());
        assert!(MainKeyJoinPlanV1::exact_challenges_v1(&mut fresh(), DOMAIN_V1, 13).is_err());
    }

    #[test]
    fn target_mutations_and_wrong_root_power_cannot_satisfy_a_byte_block() {
        for (power, count) in [(2, 65), (8, 64)] {
            let (b, source, target, _) = public_block_v1(power, count);
            let points = (0..count)
                .map(|j| {
                    b.scale
                        .mul(b.start.mul(b.step.pow(j as u128)).pow(u128::from(power)))
                })
                .collect::<Vec<_>>();
            for changed in 0..count {
                let mut delta = vec![F::ONE];
                for (j, p) in points.iter().enumerate() {
                    if j != changed {
                        delta = product_v1(&delta, &[F::ZERO.sub(*p), F::ONE]);
                    }
                }
                let mut mutant = target.clone();
                mutant.resize(mutant.len().max(delta.len()), F::ZERO);
                for (i, coefficient) in delta.iter().enumerate() {
                    mutant[i] = mutant[i].add(*coefficient);
                }
                assert!(MainKeyJoinPlanV1::quotient_v1(b, &source, &mutant).is_err());
            }
            let mut wrong_scale = b;
            wrong_scale.scale = wrong_scale.scale.add(F::ONE);
            assert!(MainKeyJoinPlanV1::quotient_v1(wrong_scale, &source, &target).is_err());
            let mut wrong_power = b;
            wrong_power.power = 1;
            assert!(MainKeyJoinPlanV1::quotient_v1(wrong_power, &source, &target).is_err());
        }
    }

    #[test]
    fn replay_sharing_and_synthetic_division_have_complete_public_work_counts() {
        let (_, plan) = plan_v1(4);
        let io_column = plan.blocks[0].target;
        assert!(
            plan.blocks[..KEY_OPENINGS_V1]
                .iter()
                .all(|b| b.source == plan.blocks[0].source)
        );
        let io_count = plan.blocks[..KEY_OPENINGS_V1]
            .iter()
            .filter(|b| b.target == io_column)
            .count();
        assert_eq!(io_count, 6);
        let streamed = plan.blocks[..KEY_OPENINGS_V1]
            .iter()
            .filter(|b| b.target != io_column)
            .collect::<Vec<_>>();
        assert_eq!(streamed.len(), 5);
        for (i, b) in streamed.iter().enumerate() {
            assert!(streamed[..i].iter().all(|other| other.target != b.target));
        }
        let replays_per_opening_phase = 1 + streamed.len();
        let composition_replays = 1 + replays_per_opening_phase + 2 + 3;
        assert_eq!(composition_replays + 2 * replays_per_opening_phase, 24);
        let n = |log: u8| (1_usize << log) + MASK_DEGREE + 1;
        let divisions: usize = plan
            .blocks
            .iter()
            .map(|b| {
                let numerator = n(b.source.log).max((n(b.target.log) - 1) * b.power as usize + 1);
                numerator * b.count
            })
            .sum();
        assert_eq!(divisions, 345_046_578);
        assert_eq!(divisions + 5 * 8 * (32 * (n(16) - 1) + 1), 431_255_898);
        let evaluation_steps: usize = plan.blocks[..KEY_OPENINGS_V1]
            .iter()
            .map(|b| n(b.target.log))
            .sum();
        assert_eq!(evaluation_steps, 1_920_520);
        // Opening evaluation plus the DEEP synthetic-division recurrence. No
        // duplicate Horner evaluation is performed in the second phase.
        assert_eq!(2 * evaluation_steps, 3_841_040);
        assert_eq!(evaluation_steps + 20 * n(16), 3_267_560);
        let native_butterflies =
            2 * ((1 << 19) / 2 * 19) + 3 * ((1 << 18) / 2 * 18) + 16 * ((1 << 16) / 2 * 16);
        assert_eq!(native_butterflies, 25_427_968);
        assert_eq!(native_butterflies + 3 * ((1 << 19) / 2 * 19), 40_370_176);
        assert!((n(19) + n(18) + n(16)) * 8 <= 2 * n(19) * 8);
    }

    #[test]
    fn complete_key_and_digest_opening_plan_has_sufficient_conditional_trace_masks() {
        let (layout, mut plan) = plan_v1(4);
        plan.check_mask_query_closure_v1().unwrap();
        let z = E::canonical([31, 5, 17, 2]).unwrap();
        let shared = layout.as_shared().unwrap();
        assert!(plan.admissible_v1(z, &shared).unwrap());
        for signature in 0..5 {
            let owner = plan.blocks[2 * signature + 1].target;
            let matching = (0..OPENINGS_V1)
                .filter(|i| {
                    let (other, _) = plan.opening_v1(*i, z).unwrap();
                    other.group == owner.group && other.column == owner.column
                })
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 5);
            assert_eq!(matching[0], 2 * signature + 1);
            assert_eq!(
                &matching[1..],
                &[
                    11 + 4 * signature,
                    12 + 4 * signature,
                    13 + 4 * signature,
                    14 + 4 * signature
                ]
            );
        }
        assert_eq!((2 + 5) * (QUERY_COUNT + 4), 980);
        assert_eq!((2 + 6) * (QUERY_COUNT + 4), 1120);
        const { assert!((2 + 6) * (QUERY_COUNT + 4) <= MASK_DEGREE + 1) };
        let old_admitted = E::from_base(goldilocks_primitive_root_v1(24).unwrap());
        assert!(
            aggregate::deep_point_is_admissible_v1(old_admitted, AGGREGATE_PARAMETERS_V1, &shared)
                .unwrap()
        );
        for block in &plan.blocks[..KEY_OPENINGS_V1] {
            assert!(
                aggregate::deep_point_is_admissible_v1(
                    MainKeyJoinPlanV1::target_point_v1(*block, old_admitted),
                    AGGREGATE_PARAMETERS_V1,
                    &shared
                )
                .unwrap()
            );
        }
        assert!(!plan.admissible_v1(old_admitted, &shared).unwrap());
        for i in KEY_OPENINGS_V1..OPENINGS_V1 {
            let (_, point) = plan.opening_v1(i, old_admitted).unwrap();
            assert_eq!(point.pow(1 << 19), E::ONE);
        }
        let chunks =
            super::super::super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
                &shared,
                AGGREGATE_PARAMETERS_V1,
            )
            .unwrap();
        let cap = shared.fri_degree_cap(AGGREGATE_PARAMETERS_V1).unwrap();
        assert_eq!(cap - chunks.stride_v1(), QUERY_COUNT + 1);
        assert_eq!(
            shared
                .fri_mask_coefficient_count(AGGREGATE_PARAMETERS_V1)
                .unwrap(),
            cap - 1
        );
        assert_eq!(32 * ((1 << 16) + MASK_DEGREE) - 8, 2_155_224);
        assert!(
            32 * ((1 << 16) + MASK_DEGREE) - 8
                < chunks.stride_v1() * AGGREGATE_PARAMETERS_V1.composition_degree_chunks
        );
        assert_eq!(
            chunks.stride_v1() * AGGREGATE_PARAMETERS_V1.composition_degree_chunks,
            3_538_122
        );
        let concentrated = plan.blocks[0].target;
        for block in &mut plan.blocks[..KEY_OPENINGS_V1] {
            block.target = concentrated;
        }
        const { assert!((2 + KEY_OPENINGS_V1) * (QUERY_COUNT + 4) > MASK_DEGREE + 1) };
        assert!(plan.check_mask_query_closure_v1().is_err());
    }

    #[test]
    fn digest_contributions_cross_chunk_boundaries_without_truncation_or_partial_errors() {
        let stride = 17;
        let cap = 24;
        let fresh = || {
            (0..6)
                .map(|_| {
                    let mut column = Vec::new();
                    column.try_reserve_exact(cap).unwrap();
                    column
                })
                .collect::<Vec<Vec<E>>>()
        };
        let mut chunks = fresh();
        let mut coefficients = vec![E::ZERO; 4 * stride - 3];
        for index in [
            0,
            stride - 1,
            stride,
            2 * stride - 1,
            2 * stride,
            3 * stride,
            4 * stride - 4,
        ] {
            coefficients[index] = E::canonical([index as u64 + 3, 5, 7, 11]).unwrap();
        }
        MainKeyJoinPlanV1::publish_chunks_v1(&mut chunks, &coefficients, stride, cap).unwrap();
        for point in [E::from_base(F(13)), E::canonical([31, 5, 17, 2]).unwrap()] {
            let eval = |values: &[E]| {
                values
                    .iter()
                    .rev()
                    .fold(E::ZERO, |v, c| v.mul(point).add(*c))
            };
            let recomposed = chunks.iter().enumerate().fold(E::ZERO, |v, (i, chunk)| {
                v.add(eval(chunk).mul(point.pow((stride * i) as u128)))
            });
            assert_eq!(recomposed, eval(&coefficients));
        }
        assert!(chunks[..3].iter().all(|c| c.len() == stride));
        assert_eq!(chunks[3].len(), stride - 3);
        assert!(chunks[4..].iter().all(Vec::is_empty));
        for failure in 0..4 {
            let mut target = fresh();
            target[0].push(E::from_base(F(29)));
            if failure == 0 {
                target[4] = Vec::new();
            }
            if failure == 1 {
                target[4].resize(stride + 1, E::ZERO);
            }
            let before = target.clone();
            let bad_length = vec![E::ZERO; stride * 6 + 1];
            let input = if failure == 2 {
                &bad_length
            } else {
                &coefficients
            };
            let attempt_stride = if failure == 3 { 0 } else { stride };
            assert!(
                MainKeyJoinPlanV1::publish_chunks_v1(&mut target, input, attempt_stride, cap)
                    .is_err()
            );
            assert_eq!(target, before);
        }
    }

    #[test]
    fn full_degree_and_additional_owner_payload_are_bounded() {
        assert_eq!(8 * ((1 << 16) + MASK_DEGREE) - 64, 538_744);
        assert_eq!(2 * ((1 << 18) + MASK_DEGREE) - 65, 527_853);
        assert_eq!(2 * ((1 << 18) + MASK_DEGREE) - 1, 527_917);
        const { assert!(8 * ((1 << 16) + MASK_DEGREE) + 1 < 589_687) };
        assert_eq!(MainKeyJoinPlanV1::PRIVATE_BYTES_V1, 99_391_016);
        assert_eq!(MainKeyJoinPlanV1::public_owner_charge_v1(), 8_388_608);
        assert_eq!(KEY_OPENINGS_V1 * core::mem::size_of::<E>(), 352);
        assert_eq!(OPENINGS_V1 * core::mem::size_of::<E>(), 992);
    }
}

/// Closed statement-only relation plan. No private values or endpoints enter it.
pub(super) struct MainKeyJoinPlanV1 {
    blocks: [BlockV1; KEY_BLOCKS_V1],
    digest: MainDigestJoinPlanV1,
}

impl MainKeyJoinPlanV1 {
    /// Explicit conservative public allowance, including simultaneous construction
    /// of the existing RFC topology and I/O declaration vectors plus transcript
    /// records, plans, alphas, supplemental openings and bounded stack copies.
    pub(super) const fn public_owner_charge_v1() -> usize {
        8 * 1024 * 1024
    }

    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        shape: ZkX509Rfc5280StarkShapeV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let (rows, channels, value_column, activity_column) =
            zk_x509_rfc_key_join_rows_v1(shape).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let io = super::super::super::main_io::compile_zk_x509_main_io_declarations_v1(statement)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        if io.declarations.len()
            != super::super::super::main_io::ZK_X509_MAIN_IO_BASE_DECLARATIONS_V1
                + super::super::super::main_io::ZK_X509_MAIN_IO_DECLARATIONS_PER_DISCLOSURE_V1
                    * usize::from(shape.disclosed_attribute_count())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut public_payload = io
            .declarations
            .capacity()
            .checked_mul(core::mem::size_of::<
                super::super::super::io_air::ZkX509IoChannelDeclarationV1,
            >())
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        for declaration in &io.declarations {
            public_payload = public_payload
                .checked_add(
                    declaration
                        .consumers
                        .capacity()
                        .checked_mul(core::mem::size_of::<
                            super::super::super::io_air::ZkX509IoEndpointV1,
                        >())
                        .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?,
                )
                .and_then(|size| {
                    size.checked_add(declaration.public_value.as_ref().map_or(0, Vec::capacity))
                })
                .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        }
        // The RFC helper's <=22,705 flat entries (each <=32 bytes) and its
        // <=64 channel tuples fit 1 MiB and are already dropped here. Reserve
        // that whole allowance plus 64 KiB for copies, plans and transcripts.
        if public_payload > Self::public_owner_charge_v1() - 1024 * 1024 - 64 * 1024 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        let rfc = layout.registered_segment(SegmentAdapterIdV1::Rfc5280, 0)?;
        let io_registration = layout.registered_segment(SegmentAdapterIdV1::ByteMemory, 0)?;
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
        let source = column(rfc, value_column)?;
        let io_value = column(io_registration, EXEC_VALUE)?;
        if source.log != 19 || io_value.log != 18 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let (real_column, active_column, real_start) = p256_real_key_input_columns_v1();
        let sink = |signature| {
            let identity =
                P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::BindingSink, 0)?;
            let mut matches =
                layout.registered_segments.iter().copied().filter(|r| {
                    p256_main_registration_from_main_layout_v1(*r).ok() == Some(identity)
                });
            let found = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            if matches.next().is_some() || found.segment.trace_log2 != 16 {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok(found)
        };
        let root = goldilocks_primitive_root_v1(19).map_err(map_transparent_error_v1)?;
        let dummy = BlockV1 {
            source,
            target: io_value,
            start: F::ONE,
            step: root,
            count: 1,
            power: 2,
            scale: F::ONE,
        };
        let mut blocks = [dummy; KEY_BLOCKS_V1];
        for index in 0..6 {
            let channel = channels[index];
            let declaration = io
                .declarations
                .get(channel as usize)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            let count = if index == 5 { 1 } else { 65 };
            if declaration.channel != channel
                || declaration.byte_len as usize != count
                || declaration.producer.role != ZkX509IoSegmentRoleV1::StrictDer
                || declaration.producer.instance != 0
                || declaration.consumers.len() != 1
                || declaration.consumers[0].role != ZkX509IoSegmentRoleV1::P256
                || declaration.consumers[0].instance != 0
                || declaration.public_value.is_some()
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let io_start =
                io.declarations[..channel as usize]
                    .iter()
                    .try_fold(0_usize, |sum, d| {
                        (d.byte_len as usize)
                            .checked_mul(1 + d.consumers.len())
                            .and_then(|n| sum.checked_add(n))
                            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
                    })?;
            let make = |source_row: usize, target: ColumnV1, target_row: usize, count: usize| {
                if source_row
                    .checked_add(count)
                    .is_none_or(|n| n > 1 << source.log)
                    || target_row
                        .checked_add(count)
                        .is_none_or(|n| n > 1 << target.log)
                {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let power = 1_u8
                    .checked_shl(u32::from(source.log - target.log))
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
                let start = root.pow(source_row as u128);
                let target_root =
                    goldilocks_primitive_root_v1(target.log).map_err(map_transparent_error_v1)?;
                if root.pow(u128::from(power)) != target_root {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let scale = target_root.pow(target_row as u128).mul(
                    start
                        .pow(u128::from(power))
                        .inv()
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                );
                Ok(BlockV1 {
                    source,
                    target,
                    start,
                    step: root,
                    count,
                    power,
                    scale,
                })
            };
            if index < 5 {
                blocks[2 * index] = make(rows[index], io_value, io_start, 65)?;
                blocks[2 * index + 1] = make(
                    rows[index] + 1,
                    column(sink(index)?, real_column)?,
                    real_start,
                    64,
                )?;
            } else {
                blocks[10] = make(rows[index], io_value, io_start, 1)?;
            }
        }
        blocks[11] = BlockV1 {
            source: column(rfc, activity_column)?,
            target: column(sink(2)?, active_column)?,
            start: F::ONE,
            step: F::ONE,
            count: 1,
            power: 1,
            scale: F::ONE,
        };
        let digest =
            MainDigestJoinPlanV1::new_v1(layout, usize::from(shape.disclosed_attribute_count()))?;
        let plan = Self { blocks, digest };
        plan.check_mask_query_closure_v1()?;
        Ok(plan)
    }

    /// Original committed owner and actual derived point for every extra opening.
    fn opening_v1(&self, index: usize, z: E) -> Result<(ColumnV1, E), ZkX509StarkErrorV1> {
        if index < KEY_OPENINGS_V1 {
            let block = self.blocks[index];
            Ok((block.target, Self::target_point_v1(block, z)))
        } else {
            self.digest.opening_v1(index - KEY_OPENINGS_V1, z)
        }
    }

    /// Conservative conditional AIR/chunk view, including all key and digest maps.
    /// This does not qualify public terminals, aborts or Fiat-Shamir zero knowledge.
    fn check_mask_query_closure_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        for index in 0..OPENINGS_V1 {
            let (owner, _) = self.opening_v1(index, E::ONE)?;
            let mut extra_sets = 0_usize;
            for other in 0..OPENINGS_V1 {
                let (candidate, _) = self.opening_v1(other, E::ONE)?;
                if owner.group == candidate.group && owner.column == candidate.column {
                    extra_sets += 1;
                }
            }
            if (2 + extra_sets)
                .checked_mul(QUERY_COUNT + 4)
                .is_none_or(|size| size > MASK_DEGREE + 1)
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
        }
        Ok(())
    }

    pub(super) fn derive_alphas_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        transcript
            .absorb(DOMAIN_V1, &[DESCRIPTOR_V1])
            .map_err(map_transparent_error_v1)?;
        for b in self.blocks {
            let mut record = [0_u8; 67];
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
            transcript
                .absorb(DOMAIN_V1, &[&record])
                .map_err(map_transparent_error_v1)?;
        }
        self.digest.absorb_plan_v1(transcript)?;
        Self::exact_challenges_v1(transcript, DOMAIN_V1, BLOCKS_V1)
    }

    fn exact_challenges_v1(
        transcript: &mut TransparentTranscriptV1,
        label: &[u8],
        count: usize,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        if count != BLOCKS_V1 && count != OPENINGS_V1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if values.capacity() != count {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for _ in 0..count {
            values.push(
                transcript
                    .challenge_fp4(label)
                    .map_err(map_transparent_error_v1)?,
            );
        }
        Ok(values)
    }

    fn target_point_v1(block: BlockV1, z: E) -> E {
        z.pow(u128::from(block.power)).mul_base(block.scale)
    }
    pub(super) fn admissible_v1(
        &self,
        z: E,
        layout: &aggregate::AggregateProofLayoutV1,
    ) -> Result<bool, ZkX509StarkErrorV1> {
        if !aggregate::deep_point_is_admissible_v1(z, AGGREGATE_PARAMETERS_V1, layout)
            .map_err(map_aggregate_error_v1)?
        {
            return Ok(false);
        }
        for index in 0..OPENINGS_V1 {
            let (_, point) = self.opening_v1(index, z)?;
            if !aggregate::deep_point_is_admissible_v1(point, AGGREGATE_PARAMETERS_V1, layout)
                .map_err(map_aggregate_error_v1)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn absorb_openings_v1(
        values: &[E; OPENINGS_V1],
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        let mut bytes = [0_u8; OPENINGS_V1 * 32];
        for (i, value) in values.iter().enumerate() {
            if !value.is_canonical() {
                return Err(ZkX509StarkErrorV1::NonCanonicalField);
            }
            for (j, word) in value.coefficients().iter().enumerate() {
                bytes[i * 32 + j * 8..i * 32 + j * 8 + 8].copy_from_slice(&word.0.to_be_bytes());
            }
        }
        transcript
            .absorb(b"zk-x509-key-join-deep-values-v1", &[&bytes])
            .map_err(map_transparent_error_v1)
    }
    pub(super) fn derive_mixes_v1(
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        Self::exact_challenges_v1(transcript, b"zk-x509-key-join-deep-mixes-v1", OPENINGS_V1)
    }
    pub(super) fn evaluate_v1(
        &self,
        groups: &[aggregate::AggregateOpenedDeepTraceGroupV1],
        z: E,
        values: &[E; OPENINGS_V1],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if alphas.len() != BLOCKS_V1 || alphas.iter().chain(values).any(|v| !v.is_canonical()) {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        let get = |column: ColumnV1| {
            groups
                .get(column.group)
                .and_then(|g| g.base_current.get(column.column))
                .copied()
                .ok_or(ZkX509StarkErrorV1::ConstraintOpening)
        };
        let mut result = E::ZERO;
        for (i, b) in self.blocks.iter().enumerate() {
            let target = if i < KEY_OPENINGS_V1 {
                values[i]
            } else {
                get(b.target)?
            };
            let mut x = b.start;
            let mut vanishing = E::ONE;
            for _ in 0..b.count {
                vanishing = vanishing.mul(z.sub(E::from_base(x)));
                x = x.mul(b.step);
            }
            result = result.add(
                alphas[i].mul(get(b.source)?.sub(target)).mul(
                    vanishing
                        .inv()
                        .ok_or(ZkX509StarkErrorV1::ConstraintOpening)?,
                ),
            );
        }
        Ok(result.add(self.digest.evaluate_v1(
            groups,
            z,
            &values[KEY_OPENINGS_V1..],
            &alphas[KEY_BLOCKS_V1..],
        )?))
    }
    pub(super) fn supplemental_v1(
        &self,
        z: E,
        values: &[E; OPENINGS_V1],
        mixes: &[E],
    ) -> Result<Vec<aggregate::AggregateSupplementalDeepOpeningV1>, ZkX509StarkErrorV1> {
        if mixes.len() != OPENINGS_V1
            || mixes.iter().chain(values).any(|v| !v.is_canonical())
            || !z.is_canonical()
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        let mut openings = Vec::new();
        openings
            .try_reserve_exact(OPENINGS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if openings.capacity() != OPENINGS_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for i in 0..OPENINGS_V1 {
            let (column, point) = self.opening_v1(i, z)?;
            openings.push(aggregate::AggregateSupplementalDeepOpeningV1 {
                group: column.group,
                column: aggregate::AggregateSupplementalColumnV1::Base(column.column),
                point,
                value: values[i],
                mix: mixes[i],
            });
        }
        Ok(openings)
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainKeyJoinPlanV1 {
    // RFC, IO, the cached SHA segment and streamed P256 coefficients coexist.
    // Three log19 columns bound that sum. Digest packing also holds one log16
    // weighted target, one power32 numerator and its deferred extension result.
    // Every source/device operation reserves this allowance before replay.
    const PRIVATE_BYTES_V1: usize = 3 * ((1 << 19) + MASK_DEGREE + 1) * 8
        + ((1 << 16) + MASK_DEGREE + 1) * 8
        + (32 * ((1 << 16) + MASK_DEGREE) + 1) * 40
        + 16 * 1024;
    fn replay_v1(
        column: ColumnV1,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let mut values = polynomials.replay_columns_coefficients_v1(
            layout,
            MainTraceColumnKindV1::Base,
            column.group,
            column.column..column.column + 1,
            sources,
            policy,
        )?;
        if values.len() != 1 || values.capacity() != 1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        let result = values.pop().ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if result.len() != (1 << column.log) + MASK_DEGREE + 1
            || result.0.capacity() != result.len()
        {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        Ok(result)
    }
    /// Replay the single I/O value column once for its six derived points,
    /// while streaming each of the five distinct P256 real-byte columns once.
    /// The caller reserves all live coefficient owners before entering here.
    fn with_target_coefficients_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        mut visit: impl FnMut(usize, &[F]) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        let io_column = self.blocks[0].target;
        let io = Self::replay_v1(io_column, layout, polynomials, sources, policy)?;
        for (i, block) in self.blocks[..KEY_OPENINGS_V1].iter().enumerate() {
            if block.target == io_column {
                visit(i, &io)?;
            } else {
                let target = Self::replay_v1(block.target, layout, polynomials, sources, policy)?;
                visit(i, &target)?;
                let signature = i / 2;
                if i % 2 != 1
                    || signature >= DIGEST_BLOCKS_V1
                    || self.digest.target_v1(signature)? != block.target
                {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                for byte in 0..4 {
                    visit(KEY_OPENINGS_V1 + 4 * signature + byte, &target)?;
                }
            }
        }
        Ok(())
    }

    fn evaluate_coefficients_v1(coefficients: &[F], point: E) -> E {
        coefficients
            .iter()
            .rev()
            .fold(E::ZERO, |sum, c| sum.mul(point).add(E::from_base(*c)))
    }
    fn quotient_v1(
        b: BlockV1,
        source: &[F],
        target: &[F],
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if source.is_empty()
            || target.is_empty()
            || !matches!(b.power, 1 | 2 | 8 | 32)
            || !(1..=65).contains(&b.count)
            || b.scale == F::ZERO
            || b.start == F::ZERO
            || b.step == F::ZERO
            || source
                .iter()
                .chain(target)
                .any(|v| F::canonical(v.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let length = source.len().max(
            (target.len() - 1)
                .checked_mul(b.power as usize)
                .and_then(|v| v.checked_add(1))
                .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?,
        );
        let mut numerator = ZeroizingMainTraceColumnV1(Vec::new());
        numerator
            .0
            .try_reserve_exact(length)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if numerator.0.capacity() != length {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        numerator.0.resize(length, F::ZERO);
        numerator.0[..source.len()].copy_from_slice(source);
        let mut power = F::ONE;
        for (j, v) in target.iter().enumerate() {
            numerator.0[j * b.power as usize] = numerator.0[j * b.power as usize].sub(v.mul(power));
            power = power.mul(b.scale);
        }
        // Sequential exact division by distinct public factors also checks every
        // individual endpoint. A later nonzero remainder cannot be cancelled by
        // a different block's Fiat-Shamir coefficient.
        let mut point = b.start;
        for _ in 0..b.count {
            let mut carry = F::ZERO;
            for value in numerator.0.iter_mut().rev() {
                let original = *value;
                *value = carry;
                carry = original.add(carry.mul(point));
            }
            if carry != F::ZERO {
                return Err(ZkX509StarkErrorV1::ConstraintOpening);
            }
            point = point.mul(b.step);
        }
        Ok(numerator)
    }
    /// Validate all capacities before any coefficient or length can change.
    fn check_chunk_destination_v1(
        chunks: &[Vec<E>],
        length: usize,
        stride: usize,
        cap: usize,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if stride == 0
            || cap < stride
            || chunks.is_empty()
            || stride
                .checked_mul(chunks.len())
                .is_none_or(|covered| length > covered)
            || chunks
                .iter()
                .any(|chunk| chunk.len() > stride || chunk.capacity() != cap)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }

    /// Add the entire coefficient polynomial at the canonical monomial stride.
    /// Native quotient checks and completion fencing precede this publication.
    fn publish_chunks_v1(
        chunks: &mut [Vec<E>],
        coefficients: &[E],
        stride: usize,
        cap: usize,
    ) -> Result<(), ZkX509StarkErrorV1> {
        Self::check_chunk_destination_v1(chunks, coefficients.len(), stride, cap)?;
        if coefficients.iter().any(|value| !value.is_canonical()) {
            return Err(ZkX509StarkErrorV1::NonCanonicalField);
        }
        for (chunk, contribution) in chunks.iter_mut().zip(coefficients.chunks(stride)) {
            // The full capacity was reserved by the composition ledger. This
            // resize cannot allocate or fail after another chunk was changed.
            if chunk.len() < contribution.len() {
                chunk.resize(contribution.len(), E::ZERO);
            }
            for (out, value) in chunk.iter_mut().zip(contribution) {
                *out = out.add(*value);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn accumulate_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        alphas: &[E],
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        accumulator: &mut [Vec<E>],
    ) -> Result<(), ZkX509StarkErrorV1> {
        if alphas.len() != BLOCKS_V1 || alphas.iter().any(|x| !x.is_canonical()) {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        main_bounded_transform::check_completion_v1(
            fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
        )?;
        let policy = policy.reserve_additional_v1(Self::PRIVATE_BYTES_V1)?;
        let length = 32 * ((1 << 16) + MASK_DEGREE) + 1;
        let shared = layout.as_shared()?;
        let cap = shared
            .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
            .map_err(map_aggregate_error_v1)?;
        let geometry = super::super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
            &shared,
            AGGREGATE_PARAMETERS_V1,
        )
        .map_err(map_aggregate_error_v1)?;
        if accumulator.len() != COMPOSITION_DEGREE_CHUNKS {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Self::check_chunk_destination_v1(accumulator, length, geometry.stride_v1(), cap)?;
        let mut deferred = ZeroizingExtensionColumnV1(Vec::new());
        deferred
            .0
            .try_reserve_exact(length)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if deferred.0.capacity() != length {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        deferred.0.resize(length, E::ZERO);
        {
            let source_column = self.blocks[0].source;
            let source = Self::replay_v1(source_column, layout, polynomials, sources, policy)?;
            let io_column = self.blocks[0].target;
            let io = Self::replay_v1(io_column, layout, polynomials, sources, policy)?;
            let mut sha_cache: Option<(ColumnV1, ZeroizingMainTraceColumnV1)> = None;
            for (i, block) in self.blocks[..KEY_OPENINGS_V1].iter().copied().enumerate() {
                if block.source != source_column {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                if block.target == io_column {
                    let quotient = Self::quotient_v1(block, &source, &io)?;
                    for (out, value) in deferred.0.iter_mut().zip(quotient.iter()) {
                        *out = out.add(alphas[i].mul_base(*value));
                    }
                } else {
                    let signature = i / 2;
                    if i % 2 != 1
                        || signature >= DIGEST_BLOCKS_V1
                        || self.digest.target_v1(signature)? != block.target
                    {
                        return Err(ZkX509StarkErrorV1::ProfileMismatch);
                    }
                    let target =
                        Self::replay_v1(block.target, layout, polynomials, sources, policy)?;
                    {
                        let quotient = Self::quotient_v1(block, &source, &target)?;
                        for (out, value) in deferred.0.iter_mut().zip(quotient.iter()) {
                            *out = out.add(alphas[i].mul_base(*value));
                        }
                    }
                    let sha_column = self.digest.source_v1(signature)?;
                    if sha_cache
                        .as_ref()
                        .is_none_or(|(column, _)| *column != sha_column)
                    {
                        // Release the prior native column before constructing its replacement.
                        drop(sha_cache.take());
                        sha_cache = Some((
                            sha_column,
                            Self::replay_v1(sha_column, layout, polynomials, sources, policy)?,
                        ));
                    }
                    let sha = &sha_cache
                        .as_ref()
                        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
                        .1;
                    let quotient = self.digest.quotient_v1(signature, sha, &target)?;
                    for (out, value) in deferred.0.iter_mut().zip(quotient.iter()) {
                        *out = out.add(alphas[KEY_BLOCKS_V1 + signature].mul_base(*value));
                    }
                }
            }
        }
        // The activity pair has different committed columns. Both byte caches
        // are dropped before these owners are allocated.
        let block = self.blocks[KEY_OPENINGS_V1];
        let source = Self::replay_v1(block.source, layout, polynomials, sources, policy)?;
        let target = Self::replay_v1(block.target, layout, polynomials, sources, policy)?;
        let quotient = Self::quotient_v1(block, &source, &target)?;
        for (out, value) in deferred.0.iter_mut().zip(quotient.iter()) {
            *out = out.add(alphas[KEY_OPENINGS_V1].mul_base(*value));
        }
        main_bounded_transform::check_completion_v1(
            fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
        )?;
        Self::publish_chunks_v1(accumulator, &deferred.0, geometry.stride_v1(), cap)
    }
    pub(super) fn open_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        z: E,
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    ) -> Result<[E; OPENINGS_V1], ZkX509StarkErrorV1> {
        let policy = policy.reserve_additional_v1(Self::PRIVATE_BYTES_V1)?;
        let mut values = [E::ZERO; OPENINGS_V1];
        self.with_target_coefficients_v1(
            layout,
            polynomials,
            sources,
            policy,
            |i, coefficients| {
                values[i] = Self::evaluate_coefficients_v1(coefficients, self.opening_v1(i, z)?.1);
                Ok(())
            },
        )?;
        main_bounded_transform::check_completion_v1(
            fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
        )?;
        Ok(values)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn accumulate_deep_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        z: E,
        values: &[E; OPENINGS_V1],
        mixes: &[E],
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        accumulator: &mut [E],
    ) -> Result<(), ZkX509StarkErrorV1> {
        if mixes.len() != OPENINGS_V1
            || mixes.iter().chain(values).any(|v| !v.is_canonical())
            || !z.is_canonical()
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        let policy = policy.reserve_additional_v1(Self::PRIVATE_BYTES_V1)?;
        let length = (1 << 19) + MASK_DEGREE + 1;
        let mut deferred = ZeroizingExtensionColumnV1(Vec::new());
        deferred
            .0
            .try_reserve_exact(length)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if deferred.0.capacity() != length {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        deferred.0.resize(length, E::ZERO);
        if accumulator.len() < length {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        self.with_target_coefficients_v1(
            layout,
            polynomials,
            sources,
            policy,
            |i, coefficients| {
                let point = self.opening_v1(i, z)?.1;
                let mut carry = E::ZERO;
                for (j, c) in coefficients.iter().enumerate().rev() {
                    deferred.0[j] = deferred.0[j].add(carry.mul(mixes[i]));
                    carry = E::from_base(*c).add(carry.mul(point));
                }
                // Synthetic division computes the actual original-column
                // evaluation as its remainder. Failure discards the clearing
                // deferred owner before the caller's accumulator is touched.
                if carry != values[i] {
                    return Err(ZkX509StarkErrorV1::ConstraintOpening);
                }
                Ok(())
            },
        )?;
        main_bounded_transform::check_completion_v1(
            fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
        )?;
        for (out, v) in accumulator.iter_mut().zip(&deferred.0) {
            *out = out.add(*v);
        }
        Ok(())
    }
}
