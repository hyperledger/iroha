//! Uniform Omega predicate over actual PIPA-R proofs of fixed A-frame test
//! circuits. These isolate wrapper binding; they are not operation A proofs or
//! lineage qualification. Full operation composition has separate gates.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::omega::{OmegaCircuit, OmegaPlan, OmegaWitness};
use iroha_pasta::{Eq, Fp, Fq, PastaAffine, msm::MemoryBudget};
use iroha_plonk::{
    Protocol, ProverConfig, ProverRandomness, Witness,
    check::{CheckMode, check},
    create_proof_owned_with_claim,
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Expression, Instance, InstanceModeV1, InstanceType, ProofSuffixV1,
        TranscriptV1, TranscriptV2,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig, statement::foreign_limbs};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, create_fold, verifier::CompactSpans,
};

#[derive(Clone)]
struct Frame(Vec<Fp>);
impl Circuit<Fp> for Frame {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let public = meta.instance_column(69);
        meta.enable_equality(public);
        (glue, public)
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let words = layouter.assign_region(
            || "fixed frame isolation",
            |mut region| {
                self.0
                    .iter()
                    .map(|value| glue.constant(&mut region, *value))
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        for (row, word) in words.into_iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}
fn coordinates(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = claim.g().coordinates().unwrap();
    foreign_limbs(&x)
        .into_iter()
        .chain(foreign_limbs(&y))
        .map(Fp::from_u128)
        .collect()
}
fn frame(part: &FoldInput<Eq>, trivial: &FoldInput<Eq>) -> Vec<Fp> {
    let mut words = vec![Fp::from(17), Fp::from(u64::from(part.source_k()))];
    words.extend(coordinates(part));
    words.extend(part.challenges());
    for _ in 0..2 {
        words.extend(coordinates(trivial));
        words.extend(trivial.challenges());
    }
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(coordinates(trivial));
    assert_eq!(words.len(), 69);
    words
}
fn is_satisfied(circuit: &OmegaCircuit, instances: &[Vec<Fq>]) -> bool {
    let assigned = synthesize(circuit, 16, Some(instances)).expect("Omega component fits k16");
    check(&assigned.cs, &assigned.tables, CheckMode::Strict)
        .unwrap()
        .is_satisfied()
}
// Current range arguments have disjoint fixed activation patterns. Evaluating
// their single input with every advice leaf set to one counts active checks,
// including honest zero limbs, independently of the witness. This is an
// inventory of this layout, not a lower bound for every possible arithmetization.
fn range_activity(
    expression: &Expression<Fq>,
    row: usize,
    fixed: &[Vec<Fq>],
    selectors: &[Vec<bool>],
) -> Fq {
    match expression {
        Expression::Constant(value) => *value,
        Expression::Selector(selector) => Fq::from(u64::from(selectors[selector.index()][row])),
        Expression::Fixed(query) => {
            let rows = &fixed[query.column_index];
            let rotated = usize::try_from(
                (i64::try_from(row).unwrap() + i64::from(query.rotation.0))
                    .rem_euclid(i64::try_from(rows.len()).unwrap()),
            )
            .unwrap();
            rows[rotated]
        }
        Expression::Advice(_) | Expression::Instance(_) => Fq::ONE,
        Expression::Negated(inner) => -range_activity(inner, row, fixed, selectors),
        Expression::Sum(left, right) => {
            range_activity(left, row, fixed, selectors)
                + range_activity(right, row, fixed, selectors)
        }
        Expression::Product(left, right) => {
            range_activity(left, row, fixed, selectors)
                * range_activity(right, row, fixed, selectors)
        }
        Expression::Scaled(inner, factor) => range_activity(inner, row, fixed, selectors) * factor,
    }
}
#[test]
#[ignore = "actual k16 A-frame component proofs and full Omega constraints; run in release"]
fn uniform_omega_binds_all_source_choices_and_complete_frame() {
    exercise_omega(false);
}

#[test]
#[ignore = "actual source proofs and complete compact Omega diagnostic; run in release"]
fn compact_omega_executes_complete_verifier_and_reports_capacity() {
    exercise_omega(true);
}

fn exercise_omega(compact: bool) {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT)
        .unwrap()
        .as_input();
    let mut fixtures = Vec::new();
    let mut binding = None;
    let mut digests = Vec::new();
    for k in [12, 14, 16] {
        let g = params.params().g()[..1 << k]
            .iter()
            .fold(Eq::default(), |sum, p| sum + Eq::from(*p));
        let part =
            FoldInput::from_opening(iroha_pasta::EqAffine::from(g), &vec![Fp::ONE; k]).unwrap();
        let values = frame(&part, &trivial);
        let circuit = Frame(values.clone());
        let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
        config.compress_selectors = false;
        let key = keygen_pk_v2(&params, &circuit, &config).unwrap();
        if let Some(expected) = &binding {
            assert_eq!(key.binding(), expected);
        } else {
            binding = Some(key.binding().clone());
        }
        digests.push(key.vk().kagemusha_digest(key.binding()).unwrap());
        let witness = Witness::from_circuit(&key, &circuit, std::slice::from_ref(&values)).unwrap();
        let proof = create_proof_owned_with_claim(
            &params,
            &key,
            witness,
            ProverRandomness::os(),
            ProverConfig::default(),
        )
        .unwrap();
        let own = FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap();
        let (fold, output) = create_fold(
            &params,
            &[part, own, trivial.clone(), trivial.clone()],
            Fq::from(91).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        output.decide(&params, MemoryBudget::DEFAULT).unwrap();
        let (x, y) = output.g().coordinates().unwrap();
        let public = vec![
            vec![Fq::from(17)],
            vec![x, y],
            output
                .challenges()
                .iter()
                .map(|value| Fq::from_repr(value.to_repr()).unwrap())
                .collect(),
        ];
        fixtures.push((
            OmegaWitness {
                key: key.vk().clone(),
                instances: values,
                length: u32::try_from(proof.proof.len()).unwrap(),
                proof: proof.proof,
                fold: fold.to_bytes(),
            },
            public,
        ));
    }
    let binding = binding.unwrap();
    let forbidden_plan = OmegaPlan::new(binding.clone(), params.clone(), vec![-Fq::ONE]).unwrap();
    let plan = OmegaPlan::new(binding, params, digests).unwrap();
    let other_keys: Vec<_> = fixtures
        .iter()
        .map(|(witness, _)| witness.key.clone())
        .collect();
    let mut fixed = None;
    for (index, (witness, public)) in fixtures.into_iter().enumerate() {
        let circuit = OmegaCircuit::new(plan.clone(), witness.clone()).unwrap();
        if compact {
            compact_diagnostic(&circuit, &public);
            continue;
        }
        assert!(is_satisfied(&circuit, &public));
        // Both keys belong to the same exact descriptor and allowlist. A key
        // swap must still fail its own transcript/opening, even while the
        // original public digest and proof are retained.
        let mut changed_key = witness.clone();
        changed_key.key = other_keys[(index + 1) % other_keys.len()].clone();
        assert!(!is_satisfied(
            &OmegaCircuit::new(plan.clone(), changed_key).unwrap(),
            &public,
        ));
        // Membership is evaluated against the complete digest computed from
        // the actual key; there is no independently supplied digest proposal.
        assert!(!is_satisfied(
            &OmegaCircuit::new(forbidden_plan.clone(), witness.clone()).unwrap(),
            &public,
        ));
        let assigned = synthesize(&circuit, 16, Some(&public)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        let shape = (
            assigned.tables.fixed().to_vec(),
            assigned.tables.selectors().to_vec(),
            assigned.tables.permutation().clone(),
            assigned.tables.advice_assigned().to_vec(),
        );
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        if let Some(expected) = &fixed {
            assert_eq!(
                &shape, expected,
                "one Omega circuit across A class keys/source choices"
            );
        } else {
            fixed = Some(shape);
        }
        let rows = assigned
            .tables
            .advice_assigned()
            .iter()
            .filter_map(|column| column.iter().rposition(|value| *value).map(|r| r + 1))
            .max()
            .unwrap();
        let lane_rows: Vec<_> = assigned
            .tables
            .advice_assigned()
            .iter()
            .map(|column| {
                column
                    .iter()
                    .rposition(|value| *value)
                    .map_or(0, |row| row + 1)
            })
            .collect();
        let cells: usize = assigned
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().filter(|value| **value).count())
            .sum();
        let range_checks: Vec<_> = assigned
            .cs
            .lookups()
            .iter()
            .map(|lookup| {
                assert_eq!(lookup.width(), 1);
                let checks = (0..65530)
                    .filter(|row| {
                        !bool::from(
                            range_activity(
                                &lookup.input_expressions()[0],
                                *row,
                                assigned.tables.fixed(),
                                assigned.tables.selectors(),
                            )
                            .is_zero(),
                        )
                    })
                    .count();
                (lookup.name(), checks)
            })
            .collect();
        println!(
            "OMEGA_RANGE_CHECKS {range_checks:?} total={}",
            range_checks.iter().map(|(_, count)| count).sum::<usize>()
        );
        let finalized = assigned
            .cs
            .finalize(assigned.tables.selectors(), true)
            .unwrap();
        let layout = CircuitDescriptorV1::from_constraint_system(
            &finalized,
            DescriptorConfig {
                curve: CurveV1::Pallas,
                k: 16,
                transcript: TranscriptV1::Blake2bChallenge255,
                instance_mode: InstanceModeV1::Direct,
                proof_suffix: ProofSuffixV1::FoldedGenerator,
            },
        )
        .unwrap();
        let descriptor = CircuitDescriptorV2::from_layout(
            layout,
            TranscriptV2::KagemushaPoseidonRp57Base,
            OmegaPlan::instance_types().to_vec(),
        )
        .unwrap();
        let protocol = Protocol::new(&descriptor).unwrap();
        println!(
            "OMEGA_COMPONENT rows={rows} cells={cells} lanes={lane_rows:?} shape={:?} estimated_proof_bytes={} estimated_transport_bytes={} actual_outer_proof=false A_frame_only=true release_qualified=false",
            protocol.shape(),
            protocol.proof_length(),
            protocol.proof_length() + 1088
        );
        for (column, row) in [(0, 0), (1, 0), (2, 0)] {
            let mut wrong = public.clone();
            wrong[column][row] += Fq::ONE;
            assert!(!is_satisfied(&circuit, &wrong));
        }
        let mut bad = witness.clone();
        bad.instances[1] = Fp::from(13);
        assert!(!is_satisfied(
            &OmegaCircuit::new(plan.clone(), bad).unwrap(),
            &public
        ));
        let mut bad = witness.clone();
        bad.length -= 1;
        assert!(!is_satisfied(
            &OmegaCircuit::new(plan.clone(), bad).unwrap(),
            &public
        ));
        let mut bad = witness;
        bad.fold[0] ^= 1;
        assert!(!is_satisfied(
            &OmegaCircuit::new(plan.clone(), bad).unwrap(),
            &public
        ));
    }
}

// The production k remains16. An explicit k17 diagnostic identifies occupancy
// without silently accepting a proof outside the fixed production domain.
fn compact_diagnostic(circuit: &OmegaCircuit, public: &[Vec<Fq>]) {
    let spans = CompactSpans::new(16_384, 65_536, 131_066).unwrap();
    let diagnostic = circuit.clone().with_compact_layout(spans);
    let assigned = synthesize(&diagnostic, 17, Some(public)).unwrap();
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let unknown = synthesize(&diagnostic.without_witnesses(), 17, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let assigned_rows = assigned.tables.advice_assigned();
    let span_used = |start: usize, end: usize| {
        assigned_rows[..10]
            .iter()
            .filter_map(|column| column[start..end].iter().rposition(|v| *v).map(|r| r + 1))
            .max()
            .unwrap_or(0)
    };
    let sponge_rows = span_used(0, 16_384).div_ceil(37) * 37;
    let arithmetic_rows = span_used(16_384, 65_536);
    let curve_rows = span_used(65_536, 131_066);
    let range_rows = assigned_rows[10]
        .iter()
        .rposition(|v| *v)
        .map_or(0, |r| r + 1);
    let total = sponge_rows + arithmetic_rows + curve_rows;
    let packed = circuit.clone().with_compact_layout(
        CompactSpans::new(sponge_rows, sponge_rows + arithmetic_rows, total).unwrap(),
    );
    let packed_assigned = synthesize(&packed, 17, Some(public)).unwrap();
    let packed_report = check(
        &packed_assigned.cs,
        &packed_assigned.tables,
        CheckMode::Strict,
    )
    .unwrap();
    assert!(
        packed_report.is_satisfied(),
        "{:?}",
        packed_report.failures().first()
    );
    let finalized = packed_assigned
        .cs
        .finalize(packed_assigned.tables.selectors(), true)
        .unwrap();
    let layout = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Pallas,
            k: 16,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .unwrap();
    let descriptor = CircuitDescriptorV2::from_layout(
        layout,
        TranscriptV2::KagemushaPoseidonRp57Base,
        OmegaPlan::instance_types().to_vec(),
    )
    .unwrap();
    let protocol = Protocol::new(&descriptor).unwrap();
    println!(
        "COMPACT_OMEGA_FULL sponge={sponge_rows} arithmetic={arithmetic_rows} curve={curve_rows} shared_total={total} range={range_rows} shape={:?} descriptor_transport={} actual_outer_proof=false actual_source_A_frame_proof=true production_k16_fit={}",
        protocol.shape(),
        protocol.proof_length() + 1088,
        total <= 65_530 && range_rows <= 65_530
    );
    if total <= 65_530 && range_rows <= 65_530 {
        assert!(is_satisfied(&packed, public));
    } else {
        assert!(synthesize(&packed, 16, Some(public)).is_err());
    }
    let mut changed = public.to_vec();
    changed[0][0] += Fq::ONE;
    let changed = synthesize(&packed, 17, Some(&changed)).unwrap();
    assert!(
        !check(&changed.cs, &changed.tables, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}
