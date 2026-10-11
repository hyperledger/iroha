//! Shared native framing, Q schema and exact circuit commitment parity.

use super::*;
use crate::{a_relation::context::ContextObjectCells, q_sigma::SigmaClass};
use iroha_pasta::PastaField;
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness,
    check::{CheckMode, check},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error as CircuitError, Layouter, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig,
    bytes::{
        chunk_segments,
        tape::{BytesChip, BytesConfig},
        variable::ActiveBytes,
    },
};
use iroha_plonk_recursion::{
    K,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};

#[derive(Clone)]
struct Constant<F>(F);
impl<F: PastaField> Circuit<F> for Constant<F> {
    type Config = (GlueConfig, Column<Instance>);
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let fixed = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, fixed);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (glue, public)
    }
    fn synthesize(
        &self,
        (glue, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), CircuitError> {
        let word = layouter.assign_region(
            || "constant source",
            |mut r| GlueChip::new(glue).constant(&mut r, self.0),
        )?;
        layouter.constrain_instance(word.cell(), public, 0)
    }
}
fn sigma_plan(k: u32, paired: bool) -> QSigmaPlan {
    let params = PinnedParams::<Eq>::derive(k).unwrap();
    let (binding, key) = keygen_vk_with_binding_v2(
        &params,
        &Constant(Fp::ONE),
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
    )
    .unwrap();
    let verifier = VerifierPlan::new(binding.clone(), params).unwrap();
    let own = SigmaClass::new(
        verifier.clone(),
        vec![(0, key.kagemusha_digest(&binding).unwrap())],
    )
    .unwrap();
    // Metadata-only test catalogs: these values never authorize a source proof.
    let incoming = paired.then(|| SigmaClass::new(verifier, vec![(1, Fq::from(73))]).unwrap());
    QSigmaPlan::new(own, incoming, &PinnedParams::derive(16).unwrap()).unwrap()
}
fn vesta_claim(source_k: u32) -> FoldInput<Eq> {
    let point = iroha_plonk::transcript::decode_point::<Eq>(
        &iroha_plonk_recursion::VESTA_TRIVIAL_GENERATOR,
    )
    .unwrap();
    FoldInput::from_opening(point, &vec![Fp::ONE; usize::try_from(source_k).unwrap()]).unwrap()
}
#[test]
fn q_parts_require_exact_plan_lengths_source_and_normalized_challenges() {
    for (k, paired) in [(12, false), (14, false), (12, true)] {
        let plan = sigma_plan(k, paired);
        let claim = vesta_claim(plan.part_source_k());
        let (x, y) = claim.g().coordinates().unwrap();
        let mut columns: Vec<_> = plan.instance_lengths().map(|n| vec![Fq::ZERO; n]).into();
        columns[0][plan.challenge_range()].copy_from_slice(
            &claim
                .challenges()
                .map(|v| Fq::from_repr(v.to_repr()).unwrap()),
        );
        columns[1] = vec![x, y];
        columns[3][0] = Fq::ONE;
        columns[4][0] = Fq::from(u64::from(plan.part_source_k()));
        assert_eq!(q_sigma_part(&columns, &plan).unwrap(), claim);
        for column in 0..5 {
            for extend in [false, true] {
                let mut bad = columns.clone();
                if extend {
                    bad[column].push(Fq::ZERO);
                } else {
                    bad[column].pop();
                }
                assert_eq!(q_sigma_part(&bad, &plan), Err(Error::Input));
            }
        }
        for mutation in 0..6 {
            let mut bad = columns.clone();
            match mutation {
                0 => {
                    bad.pop();
                }
                1 => bad[3][0] = Fq::ZERO,
                2 => bad[4][0] += Fq::ONE,
                3 => bad[1] = vec![Fq::ZERO; 2],
                4 => bad[0][plan.challenge_range().end - 1] = Fq::ZERO,
                _ => bad[0][plan.challenge_range().start] = if paired { Fq::ZERO } else { Fq::ONE },
            }
            assert_eq!(
                q_sigma_part(&bad, &plan),
                Err(Error::Input),
                "source={k} paired={paired} mutation={mutation}"
            );
        }
    }
}

#[derive(Clone)]
struct Commitments {
    known: bool,
    raw: Vec<u8>,
    values: Vec<Fp>,
}
impl Commitments {
    fn value<T>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn specs() -> [ContextObjectSpec; 3] {
        [
            ContextObjectSpec {
                tag: 3,
                capacity: 37,
            },
            ContextObjectSpec {
                tag: 4,
                capacity: 53,
            },
            ContextObjectSpec {
                tag: 5,
                capacity: 96,
            },
        ]
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        let [exact, active, internal] = Self::specs();
        vec![
            exact_context(exact, Fp::from(17), &self.raw)
                .unwrap()
                .into_iter()
                .chain(active_context(active, Fp::from(19), &self.raw).unwrap())
                .chain(internal_context(internal, &self.values).unwrap())
                .collect(),
        ]
    }
}
impl Circuit<Fp> for Commitments {
    type Config = (VerifierConfig<Ep>, BytesConfig, Column<Instance>);
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(9);
        meta.enable_equality(public);
        (verifier, bytes, public)
    }
    fn synthesize(
        &self,
        (config, bytes, public): Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), CircuitError> {
        let mut chip = VerifierChip::new(config);
        let mut bytes = BytesChip::new(bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "same exact native/circuit commitments",
            |mut r| {
                let raw = self
                    .raw
                    .iter()
                    .copied()
                    .map(|v| self.value(v))
                    .collect::<Vec<_>>();
                let run = bytes.run(&mut r, &raw, &chunk_segments(0, raw.len()), &[])?;
                let [exact, active, internal] = Self::specs();
                let digest = chip
                    .uint()
                    .glue()
                    .witness(&mut r, self.value(Fp::from(17)))?;
                let exact =
                    ContextObjectCells::from_exact_run(&mut chip, &mut r, exact, &digest, &run)?;
                let source = if self.known {
                    Value::known(self.raw.clone())
                } else {
                    Value::unknown()
                };
                let active_raw =
                    ActiveBytes::assign(&mut chip.uint(), &mut bytes, &mut r, 53, &source, &[])?;
                let digest = chip
                    .uint()
                    .glue()
                    .witness(&mut r, self.value(Fp::from(19)))?;
                let active = ContextObjectCells::from_active(
                    &mut chip,
                    &mut r,
                    active,
                    &digest,
                    &active_raw,
                )?;
                let values = self
                    .values
                    .iter()
                    .copied()
                    .map(|v| self.value(v))
                    .collect::<Vec<_>>();
                let values = chip.uint().glue().witnesses(&mut r, &values)?;
                let internal =
                    ContextObjectCells::from_internal_words(&mut chip, &mut r, internal, &values)?;
                Ok([exact, active, internal]
                    .into_iter()
                    .flat_map(|v| v.commitment_words())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, i)?;
        }
        Ok(())
    }
}
#[test]
fn native_context_commitments_match_circuit_and_reject_wrong_schema() {
    let c = Commitments {
        known: true,
        raw: (0..37).collect(),
        values: vec![Fp::ONE, Fp::from(2), Fp::from(3)],
    };
    let public = c.public();
    let assigned = synthesize(&c, 16, Some(&public)).unwrap();
    assert!(
        check(&assigned.cs, &assigned.tables, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    let [exact, active, internal] = Commitments::specs();
    assert!(exact_context(exact, Fp::ONE, &c.raw[..36]).is_err());
    assert!(active_context(active, Fp::ONE, &[0; 54]).is_err());
    assert!(internal_context(internal, &c.values[..2]).is_err());
    for spec in [exact, active, internal] {
        let invalid = ContextObjectSpec { tag: 0, ..spec };
        assert!(exact_context(invalid, Fp::ONE, &c.raw).is_err());
        assert!(active_context(invalid, Fp::ONE, &[]).is_err());
        assert!(internal_context(invalid, &c.values).is_err());
    }
    let mut changed = c.raw.clone();
    changed[36] ^= 1;
    assert_ne!(
        active_context(active, Fp::ONE, &changed).unwrap(),
        active_context(active, Fp::ONE, &c.raw).unwrap()
    );
    changed.pop();
    assert_ne!(
        active_context(active, Fp::ONE, &changed).unwrap(),
        active_context(active, Fp::ONE, &c.raw).unwrap()
    );
    assert_ne!(
        internal_context(internal, &c.values).unwrap()[2],
        exact_context(internal, Fp::ONE, &[0; 96]).unwrap()[2]
    );
}

#[test]
fn native_modes_claim_words_and_terminal_frames_preserve_exact_fields() {
    assert_eq!(
        mode_words(IncomingMode::Accept),
        [Fp::ONE, Fp::ZERO, Fp::ZERO]
    );
    assert_eq!(
        mode_words(IncomingMode::Trivial),
        [Fp::ZERO, Fp::ONE, Fp::ZERO]
    );
    assert_eq!(
        mode_words(IncomingMode::Corrected),
        [Fp::ZERO, Fp::ZERO, Fp::ONE]
    );
    assert_eq!(frame(&[1, 2, 3]).unwrap(), [3, 0, 0, 0, 1, 2, 3]);
    let point = iroha_plonk::transcript::decode_point::<Ep>(
        &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
    )
    .unwrap();
    let p = FoldInput::from_normalized(point, 16, [Fq::ONE; K]).unwrap();
    let mut words = vec![];
    push_pallas(&mut words, &p).unwrap();
    assert_eq!(words.len(), 35);
    assert_eq!(words[0], Fp::from(16));
    let public = core::array::from_fn(|i| Fp::from(u64::try_from(i).unwrap()));
    let mut expected = public.to_vec();
    expected.extend(&words[1..]);
    assert_eq!(
        terminal_digest(&public, &p).unwrap(),
        hash_with_domain(crate::a_relation::LINEAGE_DOMAIN, &expected)
    );
    let short = FoldInput::from_opening(point, &[Fq::ONE; 12]).unwrap();
    assert!(push_pallas(&mut vec![], &short).is_err());
    let v = vesta_claim(16);
    assert_eq!(vesta_words(&v).unwrap().len(), 20);
    let acc = AccumulatorT::new(*v.g(), *v.challenges()).unwrap();
    let columns = omega_instances(Fp::from(43), &acc).unwrap();
    assert_eq!(columns.iter().map(Vec::len).collect::<Vec<_>>(), [1, 2, 16]);
    assert_eq!(columns[0], [Fq::from(43)]);
    assert_eq!(columns[2], vec![Fq::ONE; 16]);
    let internal = internal_public(&PinnedParams::derive(16).unwrap(), Fp::from(47), &v).unwrap();
    assert_eq!(internal.len(), 69);
    assert_eq!(internal[..2], [Fp::from(47), Fp::from(16)]);
    assert_eq!(internal[2..22], vesta_words(&v).unwrap());
    assert_eq!(internal[22..42], internal[42..62]);
    assert_eq!(internal[62..65], [Fp::ZERO, Fp::ONE, Fp::ZERO]);
    assert_eq!(internal[65..], internal[22..26]);
}

#[test]
fn both_original_proof_openings_decide_and_reject_mutation() {
    macro_rules! original {
        ($curve:ty, $scalar:ty, $open:ident) => {{
            let params = PinnedParams::<$curve>::derive(8).unwrap();
            let circuit = Constant(<$scalar>::ONE);
            let key = keygen_pk_v2(
                &params,
                &circuit,
                &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
            )
            .unwrap();
            let public = vec![vec![<$scalar>::ONE]];
            let proof = create_proof_owned_with_claim(
                &params,
                &key,
                Witness::from_circuit(&key, &circuit, &public).unwrap(),
                ProverRandomness::os(),
                ProverConfig::default(),
            )
            .unwrap();
            let opening = $open(
                &params,
                key.binding(),
                key.vk(),
                &public,
                &proof.proof,
                MemoryBudget::DEFAULT,
            )
            .unwrap();
            assert_eq!(opening.source_k(), 8);
            assert!(opening.decide(&params, MemoryBudget::DEFAULT).is_ok());
            assert_eq!(
                $open(
                    &params,
                    key.binding(),
                    key.vk(),
                    &[vec![<$scalar>::from(2)]],
                    &proof.proof,
                    MemoryBudget::DEFAULT
                ),
                Err(Error::Proof)
            );
            assert_eq!(
                $open(
                    &params,
                    key.binding(),
                    key.vk(),
                    &public,
                    &proof.proof[..proof.proof.len() - 1],
                    MemoryBudget::DEFAULT
                ),
                Err(Error::Proof)
            );
        }};
    }
    original!(Ep, Fq, opening_pallas);
    original!(Eq, Fp, opening_vesta);
}

// Constructor-only Q metadata. No source proof or installed artifact is admitted.
#[derive(Clone)]
struct StageMetadata(Vec<usize>);
impl Circuit<Fq> for StageMetadata {
    type Config = ();
    type Params = Vec<usize>;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> Self::Params {
        self.0.clone()
    }
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) {
        Self::configure_with_params(meta, vec![1]);
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fq>, lengths: Vec<usize>) {
        for length in lengths {
            meta.instance_column(length);
        }
    }
    fn synthesize(&self, (): (), _: impl Layouter<Fq>) -> Result<(), CircuitError> {
        Ok(())
    }
}

#[test]
fn stage_links_bind_fixed_ordinal_context_and_every_current_claim_limb() {
    use crate::a_relation::{AProofPlan, QProofPlan};
    use iroha_plonk_recursion::obligation::ledger::Variant;
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let sigma = sigma_plan(12, false);
    let (binding, key) = keygen_vk_with_binding_v2(
        &params,
        &StageMetadata(sigma.instance_lengths().to_vec()),
        &KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let q = QProofPlan::new(VerifierPlan::new(binding, params.clone()).unwrap(), key).unwrap();
    let operation = AProofPlan::new(Variant::Bootstrap, sigma, vec![q], None, &params).unwrap();
    let plan = ContextPlan::with_schedule(
        operation,
        vec![vec![0], vec![], vec![], vec![]],
        None,
        vec![],
    )
    .unwrap();
    let current = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let base = Fp::from(91);
    let mut digests = Vec::new();
    for stage in 0..3 {
        let actual = stage_digest(&plan, stage, base, &current).unwrap();
        let mut words = vec![
            Fp::ONE,
            plan.schema()[1],
            Fp::from(u64::try_from(stage + 1).unwrap()),
            base,
        ];
        push_pallas(&mut words, &current.as_input()).unwrap();
        assert_eq!(
            actual,
            hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &words)
        );
        assert_ne!(
            actual,
            stage_digest(&plan, stage, base + Fp::ONE, &current).unwrap()
        );
        assert!(!digests.contains(&actual));
        digests.push(actual);
        let mut encoded = current.to_bytes();
        // Negate the canonical nonidentity Pasta point via its sign bit.
        encoded[31] ^= 0x80;
        let changed = AccumulatorT::from_bytes(&encoded).unwrap();
        assert_ne!(changed.g(), current.g());
        assert_ne!(actual, stage_digest(&plan, stage, base, &changed).unwrap());
        for challenge in 0..16 {
            let mut encoded = current.to_bytes();
            encoded[32 + 32 * challenge] = 2;
            let changed = AccumulatorT::from_bytes(&encoded).unwrap();
            assert_ne!(actual, stage_digest(&plan, stage, base, &changed).unwrap());
        }
    }
    for stage in [3, 4, usize::MAX] {
        assert_eq!(
            stage_digest(&plan, stage, base, &current),
            Err(Error::Input)
        );
    }
}
