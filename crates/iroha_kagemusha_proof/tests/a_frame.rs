//! A frame binding only: canonical lineage digest, foreign limbs and fixed fillers.
//! Full operation acceptance additionally requires the operation relation and
//! actual hard Q/predecessor proofs tested by the composition suites.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::a_relation::{
    AFramePlan, AOutputCells, IncomingVestaCells, LINEAGE_DOMAIN, LineagePublicCells,
    VestaClaimCells, lineage_digest,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{
        CircuitDescriptorV1, Column, ConstraintSystem, CurveV1, DescriptorConfig, Instance,
        InstanceModeV1, ProofSuffixV1, TranscriptV1,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    transcript::decode_point,
};
use iroha_plonk_gadgets::statement::foreign_limbs;
use iroha_plonk_recursion::{
    K, PALLAS_TRIVIAL_GENERATOR, VESTA_TRIVIAL_GENERATOR,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::{ModeCells, ledger::Variant},
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Frame {
    plan: AFramePlan,
    fields: [Fp; 18],
    known: bool,
}
impl Frame {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    fn words(&self) -> Vec<Fp> {
        let (px, py) = decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR)
            .unwrap()
            .coordinates()
            .unwrap();
        let scalar = Fq::from(7);
        let limbs = foreign_limbs(&scalar).map(Fp::from_u128);
        let mut digest = self.fields.to_vec();
        digest.extend([px, py]);
        for _ in 0..K {
            digest.extend(limbs);
        }
        let da = hash_with_domain(LINEAGE_DOMAIN, &digest);
        let point = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
        let (x, y) = point.coordinates().unwrap();
        let coordinates = [x, y]
            .into_iter()
            .flat_map(|v| foreign_limbs(&v).map(Fp::from_u128))
            .collect::<Vec<_>>();
        let mut out = vec![da, Fp::from(u64::from(self.plan.part_source_k()))];
        out.extend(coordinates.clone());
        out.extend((0..K).map(|i| {
            if i < K - self.plan.part_source_k() as usize {
                Fp::ZERO
            } else {
                Fp::ONE
            }
        }));
        out.extend(coordinates.clone());
        out.extend([Fp::ONE; 16]);
        out.extend(coordinates.clone());
        out.extend([Fp::ONE; 16]);
        out.extend(if self.plan.has_incoming() {
            [Fp::ONE, Fp::ZERO, Fp::ZERO]
        } else {
            [Fp::ZERO, Fp::ONE, Fp::ZERO]
        });
        out.extend(coordinates);
        out
    }
}
fn scalar(
    chip: &mut VerifierChip<Ep>,
    region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    v: Value<Fq>,
) -> Result<ScalarCells<Ep>, Error> {
    let lo = chip
        .uint()
        .assign::<128>(region, v.map(|v| foreign_limbs(&v)[0]))?;
    let hi = chip
        .uint()
        .assign::<127>(region, v.map(|v| foreign_limbs(&v)[1]))?;
    ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)
}
impl Circuit<Fp> for Frame {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure(meta);
        let public = meta.instance_column(AFramePlan::instance_length());
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let words = layouter.assign_region(
            || "A public binding",
            |mut region| {
                let fields = self
                    .fields
                    .iter()
                    .map(|v| chip.uint().glue().witness(&mut region, self.value(*v)))
                    .collect::<Result<Vec<_>, _>>()?;
                let public = LineagePublicCells::constrain(
                    &mut chip.uint(),
                    &mut region,
                    &fields.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let p = chip.witness_point(
                    &mut region,
                    self.value(Ep::from(
                        decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR).unwrap(),
                    )),
                )?;
                let mut pu = Vec::new();
                for _ in 0..K {
                    pu.push(scalar(&mut chip, &mut region, self.value(Fq::from(7)))?);
                }
                let p = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut region,
                    16,
                    p,
                    pu.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let digest = lineage_digest(&mut chip, &mut region, &public, &p)?;
                let trivial = VestaClaimCells::trivial(&mut chip, &mut region)?;
                let mut u = Vec::new();
                for i in 0..K {
                    u.push(chip.uint().glue().witness(
                        &mut region,
                        self.value(if i < K - self.plan.part_source_k() as usize {
                            Fp::ZERO
                        } else {
                            Fp::ONE
                        }),
                    )?);
                }
                let part = VestaClaimCells::constrain(
                    &mut chip,
                    &mut region,
                    self.plan.part_source_k(),
                    trivial.coordinates().clone(),
                    u.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let incoming = if self.plan.has_incoming() {
                    let mut mode = Vec::new();
                    for v in [Fp::ONE, Fp::ZERO, Fp::ZERO] {
                        mode.push(chip.uint().glue().witness(&mut region, self.value(v))?);
                    }
                    Some(IncomingVestaCells {
                        claim: trivial.clone(),
                        mode: ModeCells::constrain(
                            chip.uint().glue(),
                            &mut region,
                            &mode.try_into().map_err(|_| Error::Synthesis)?,
                        )?,
                        corrected: trivial.coordinates().clone(),
                    })
                } else {
                    None
                };
                AOutputCells {
                    digest,
                    sigma_part: part,
                    predecessor: self.plan.has_predecessor().then_some(trivial),
                    incoming,
                }
                .words(&mut chip, &mut region, self.plan)
            },
        )?;
        for (row, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}

fn frame(variant: Variant) -> Frame {
    let folded = matches!(
        variant,
        Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveReceive
    );
    let mut fields = core::array::from_fn(|i| Fp::from(u64::try_from(i + 1).unwrap()));
    fields[0] = Fp::ONE;
    Frame {
        plan: AFramePlan::new(variant, if folded { 16 } else { 12 }).unwrap(),
        fields,
        known: true,
    }
}
#[test]
fn all_fourteen_variants_share_one_frame_and_descriptor() {
    let mut descriptor = None;
    for variant in Variant::ALL {
        let circuit = frame(variant);
        let values = [circuit.words()];
        assert_eq!(values[0].len(), 69);
        let assigned = synthesize(&circuit, 16, Some(&values)).unwrap();
        assert!(
            iroha_plonk::check::check(&assigned.cs, &assigned.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let cs = assigned
            .cs
            .finalize(assigned.tables.selectors(), false)
            .unwrap();
        let d = CircuitDescriptorV1::from_constraint_system(
            &cs,
            DescriptorConfig {
                curve: CurveV1::Vesta,
                k: 16,
                transcript: TranscriptV1::Blake2bChallenge255,
                instance_mode: InstanceModeV1::Direct,
                proof_suffix: ProofSuffixV1::FoldedGenerator,
            },
        )
        .unwrap();
        if let Some(expected) = &descriptor {
            assert_eq!(&d, expected);
        } else {
            descriptor = Some(d);
        }
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(
            assigned.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert_eq!(AFramePlan::part_range(), 1..22);
        assert_eq!(AFramePlan::predecessor_range(), 22..42);
        assert_eq!(AFramePlan::incoming_range(), 42..69);
        assert!(
            AFramePlan::new(
                variant,
                if circuit.plan.part_source_k() == 16 {
                    12
                } else {
                    16
                }
            )
            .is_err()
        );
    }
}
#[test]
fn lineage_digest_and_every_exported_word_are_bound() {
    let circuit = frame(Variant::Bootstrap);
    let values = [circuit.words()];
    for index in 0..69 {
        let mut changed = values.clone();
        changed[0][index] += Fp::ONE;
        assert!(
            !check_circuit(&circuit, 16, &changed, CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "export{index}"
        );
    }
    for index in 0..18 {
        let mut changed = circuit.clone();
        changed.fields[index] += Fp::ONE;
        assert!(
            !check_circuit(&changed, 16, &values, CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "lineagefield{index}"
        );
    }
    for (index, bits) in [(1, 128), (2, 128), (9, 128), (13, 104), (14, 128)] {
        let mut changed = circuit.clone();
        changed.fields[index] = Fp::from(2).pow_vartime([bits]);
        let changed_values = [changed.words()];
        assert!(
            !check_circuit(&changed, 16, &changed_values, CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "width{index}"
        );
    }
}
