//! Genuine PIPA-R proofs under two different keys exercise total transport verification.
//! The tiny source binds public columns only; it is not an admitted Omega relation.

use super::*;
use crate::a_relation::{LINEAGE_DOMAIN, QProofPlan, binding::tests::sigma_fixture};
use iroha_pasta::{msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    VerifyingKey, Witness,
    keys::{KeygenConfigV2, keygen_pk_v2},
    prover::{ProverConfig, ProverRandomness, create_proof_owned},
    verify_full,
};
use iroha_plonk_gadgets::GlueConfig;

#[derive(Clone)]
struct Export {
    public: Vec<Vec<Fq>>,
    salt: Fq,
    known: bool,
}
impl Circuit<Fq> for Export {
    type Config = (GlueConfig, Vec<Column<Instance>>);
    type Params = Vec<usize>;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> Self::Params {
        self.public.iter().map(Vec::len).collect()
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, vec![1, 2, 16])
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fq>, lengths: Vec<usize>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let fixed = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, fixed);
        let public = lengths
            .into_iter()
            .map(|len| {
                let column = meta.instance_column(len);
                meta.enable_equality(column);
                column
            })
            .collect();
        (glue, public)
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let words = layouter.assign_region(
            || "key-separated source",
            |mut region| {
                glue.constant(&mut region, self.salt)?;
                self.public
                    .iter()
                    .flatten()
                    .map(|value| {
                        glue.witness(
                            &mut region,
                            if self.known {
                                Value::known(*value)
                            } else {
                                Value::unknown()
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        let mut cursor = 0;
        for (column, values) in public.into_iter().zip(&self.public) {
            for row in 0..values.len() {
                layouter.constrain_instance(words[cursor].cell(), column, row)?;
                cursor += 1;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Verify {
    operation: AProofPlan,
    key: VerifyingKey<Ep>,
    bytes: Vec<u8>,
    trusted: Fp,
    decoded_key: Fp,
    known: bool,
}
impl Circuit<Fp> for Verify {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 4).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "total trusted-key transport verifier",
            |mut region| {
                let value = |v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                };
                let trusted = chip
                    .uint()
                    .glue()
                    .witness(&mut region, value(self.trusted))?;
                let decoded_key = chip
                    .uint()
                    .glue()
                    .witness(&mut region, value(self.decoded_key))?;
                let plan = IncomingTransportPlan::new(&self.operation)?;
                let values = self
                    .bytes
                    .iter()
                    .map(|b| {
                        if self.known {
                            Value::known(*b)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &values,
                    &chunk_segments(0, values.len()),
                    &ConsumingProofCells::omega_segments(plan.verifier().proof_length())?,
                )?;
                let decoded = plan.decode(&mut chip, &mut region, &run, &decoded_key)?;
                let key = chip.constant_key(&mut region, plan.verifier(), &self.key)?;
                Ok(decoded
                    .verify(&mut chip, &mut region, &self.operation, &key, &trusted)?
                    .valid
                    .word()
                    .clone())
            },
        )?;
        layouter.constrain_instance(output.cell(), config.public, 0)
    }
}

#[test]
fn actual_foreign_key_proof_soft_fails_but_substituted_verifier_key_is_hard_rejected() {
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let config = KeygenConfigV2::pipa_r(vec![
        InstanceType::Bounded,
        InstanceType::Field,
        InstanceType::Bounded,
    ]);
    let blank = Export {
        public: vec![vec![Fq::ZERO; 1], vec![Fq::ZERO; 2], vec![Fq::ZERO; 16]],
        salt: Fq::ONE,
        known: true,
    };
    let key = keygen_pk_v2(&params, &blank, &config).unwrap();
    let other_source = Export {
        salt: Fq::from(2),
        ..blank.clone()
    };
    let other = keygen_pk_v2(&params, &other_source, &config).unwrap();
    assert_eq!(key.binding(), other.binding());
    let trusted = key.vk().kagemusha_digest(key.binding()).unwrap();
    let foreign = other.vk().kagemusha_digest(other.binding()).unwrap();
    assert_ne!(trusted, foreign);
    let p = AccumulatorT::<Ep>::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let vparams = PinnedParams::<Eq>::derive(16).unwrap();
    let v = AccumulatorT::<Eq>::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
    let public = |digest| {
        let mut fields = vec![Fp::ZERO; 18];
        fields[0] = Fp::ONE;
        fields[17] = digest;
        let (x, y) = p.g().coordinates().unwrap();
        fields.extend([x, y]);
        for challenge in p.challenges() {
            fields.extend(foreign_limbs(challenge).map(Fp::from_u128));
        }
        let digest = hash_with_domain(LINEAGE_DOMAIN, &fields);
        let (x, y) = v.g().coordinates().unwrap();
        vec![
            vec![Fq::from_repr(digest.to_repr()).unwrap()],
            vec![x, y],
            v.challenges()
                .iter()
                .map(|v| Fq::from_repr(v.to_repr()).unwrap())
                .collect(),
        ]
    };
    let make_proof = |key: &iroha_plonk::ProvingKey<Ep>, source: &Export, digest| {
        let source = Export {
            public: public(digest),
            ..source.clone()
        };
        let proof = create_proof_owned(
            &params,
            key,
            Witness::from_circuit(key, &source, &source.public).unwrap(),
            ProverRandomness::os(),
            ProverConfig::default(),
        )
        .unwrap();
        verify_full(
            &params,
            key.binding(),
            key.vk(),
            &source.public,
            &proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        proof
    };
    let honest = make_proof(&key, &blank, trusted);
    let foreign_proof = make_proof(&other, &other_source, foreign);
    // Isolate key substitution from a changed lineage digest: this proof is
    // valid under the foreign key for the exact trusted public instances.
    let foreign_same_public = make_proof(&other, &other_source, trusted);
    let sigma = sigma_fixture();
    let qsource = Export {
        public: sigma.instance_lengths().map(|n| vec![Fq::ZERO; n]).to_vec(),
        ..blank
    };
    let qkey = keygen_pk_v2(
        &params,
        &qsource,
        &KeygenConfigV2::pipa_r(crate::q_sigma::QSigmaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let q = QProofPlan::new(
        VerifierPlan::new(qkey.binding().clone(), params.clone()).unwrap(),
        qkey.vk().clone(),
    )
    .unwrap();
    let operation = AProofPlan::new(
        Variant::Receive,
        sigma,
        vec![q],
        Some(VerifierPlan::new(key.binding().clone(), params.clone()).unwrap()),
        &params,
    )
    .unwrap();
    let tape = |proof: &[u8]| {
        let mut payload = vec![0; 320];
        payload[..2].copy_from_slice(&1_u16.to_le_bytes());
        payload[162] = 4;
        payload.extend(proof);
        payload.extend(p.to_bytes());
        payload.extend(v.to_bytes());
        let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        bytes.extend(payload);
        bytes
    };
    let circuit = Verify {
        operation,
        key: key.vk().clone(),
        bytes: tape(&honest),
        trusted,
        decoded_key: trusted,
        known: true,
    };
    let baseline = synthesize(&circuit, 16, None).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(baseline.tables.fixed(), unknown.tables.fixed());
    assert_eq!(baseline.tables.permutation(), unknown.tables.permutation());
    for (case, expected) in [
        (circuit.clone(), true),
        (
            Verify {
                bytes: tape(&foreign_same_public),
                ..circuit.clone()
            },
            false,
        ),
        (
            Verify {
                bytes: tape(&foreign_proof),
                ..circuit.clone()
            },
            false,
        ),
        (
            Verify {
                decoded_key: foreign,
                bytes: tape(&foreign_proof),
                ..circuit.clone()
            },
            false,
        ),
    ] {
        let public = vec![vec![Fp::from(u64::from(expected))]];
        assert!(
            check_circuit(&case, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        assert!(
            !check_circuit(
                &case,
                16,
                &[vec![Fp::from(u64::from(!expected))]],
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
    }
    let wrong_key = Verify {
        key: other.vk().clone(),
        bytes: tape(&foreign_proof),
        decoded_key: foreign,
        ..circuit
    };
    for verdict in [Fp::ZERO, Fp::ONE] {
        assert!(
            !check_circuit(&wrong_key, 16, &[vec![verdict]], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}
