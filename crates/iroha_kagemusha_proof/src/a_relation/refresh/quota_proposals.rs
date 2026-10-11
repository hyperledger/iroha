//! Quota root proposals stay bound to mandatory original owners and fixed schema.

use super::*;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::synthesize,
};

#[derive(Clone)]
struct Claims {
    originals: Originals,
    plan: ContextPlan,
    stage: usize,
    values: Vec<[Fp; 3]>,
    tuple: [Fp; 5],
    bind_originals: bool,
}
impl Circuit<Fp> for Claims {
    type Config = OriginalConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            originals: self.originals.without_witnesses(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let verifier =
            iroha_plonk_recursion::verifier::VerifierConfig::configure_serialized_foreign_tagged(
                meta, 3,
            )
            .unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = iroha_plonk_gadgets::bytes::tape::BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(18);
        meta.enable_equality(public);
        OriginalConfig {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let value = |v| {
            if self.originals.known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        };
        let claims = layouter.assign_region(
            || "quota root proposal boundary",
            |mut r| {
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut r, &self.tuple.map(value))?;
                let tuple = QuotaCommitmentCells {
                    previous_usage: fields[0].clone(),
                    windows: fields[1].clone(),
                    successor_usage: fields[2].clone(),
                    issued: fields[3].clone(),
                    window_count: fields[4].clone(),
                };
                let values = self.values.iter().map(|v| v.map(value)).collect::<Vec<_>>();
                let proposed = RefreshObjects::quota_root_claims(
                    &mut chip, &mut r, &self.plan, self.stage, &values, &tuple,
                )?;
                assert!(
                    proposed.originals().is_err(),
                    "root proposals cannot supply signed fields"
                );
                if self.bind_originals {
                    let tapes = self.originals.sources.each_ref().map(|s| {
                        s.iter()
                            .map(|v| {
                                if self.originals.known {
                                    Value::known(*v)
                                } else {
                                    Value::unknown()
                                }
                            })
                            .collect::<Vec<_>>()
                    });
                    let actual = RefreshObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut r,
                        Variant::RefreshQuotaShare,
                        tapes.each_ref().map(Vec::as_slice),
                    )?
                    .with_quota_commitment(&mut chip, &mut r, &tuple)?;
                    for (actual, proposed) in actual.context().iter().zip(proposed.context()) {
                        for (a, p) in actual
                            .commitment_words()
                            .iter()
                            .zip(proposed.commitment_words())
                        {
                            GlueChip::assert_equal(&mut r, a, &p)?;
                        }
                    }
                }
                Ok(proposed
                    .context()
                    .iter()
                    .flat_map(ContextObjectCells::commitment_words)
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, claim) in claims.iter().enumerate() {
            layouter.constrain_instance(claim.cell(), config.public, i)?;
        }
        Ok(())
    }
}
impl Claims {
    fn fixture() -> Self {
        let variant = Variant::RefreshQuotaShare;
        let policy = OwnPolicy::new([3, 4], Affine::GENERATOR).unwrap();
        let operation = operation(
            variant,
            &RefreshStagePlan::signature_schemas(policy).unwrap(),
        );
        let groups = tasks(variant);
        let mut partition = vec![vec![0], vec![1], vec![2]];
        partition.resize_with(groups.len(), Vec::new);
        let plan = ContextPlan::with_schedule(
            operation,
            partition,
            Some(0),
            RefreshObjects::context_specs(variant).unwrap(),
        )
        .unwrap()
        .with_operation_tasks(groups)
        .unwrap();
        let originals = originals(variant);
        let mut values = original_public(&originals)
            .chunks_exact(3)
            .map(|v| v.try_into().unwrap())
            .collect::<Vec<[Fp; 3]>>();
        let tuple = [
            Fp::from(17),
            Fp::from(18),
            Fp::from(19),
            Fp::from(201),
            Fp::ONE,
        ];
        let mut framed = vec![Fp::from(6), Fp::from(5)];
        framed.extend(tuple);
        let digest =
            iroha_pasta::poseidon::hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &framed);
        values.push([digest, Fp::from(160), digest]);
        Self {
            originals,
            plan,
            stage: 3,
            values,
            tuple,
            bind_originals: true,
        }
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![self.values.iter().flatten().copied().collect()]
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        check_circuit(self, 16, public, CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}

#[test]
fn quota_root_proposals_bind_every_original_triple_and_auxiliary_field() {
    let c = Claims::fixture();
    let public = c.public();
    assert!(c.accepts(&public));
    for slot in 0..5 {
        for word in 0..3 {
            let mut bad = c.clone();
            bad.values[slot][word] += Fp::ONE;
            assert!(
                !bad.accepts(&bad.public()),
                "original {slot} word {word} cannot be spliced"
            );
        }
    }
    for word in 0..3 {
        let mut bad = c.clone();
        bad.values[5][word] += Fp::ONE;
        assert!(!bad.accepts(&bad.public()), "auxiliary word {word}");
    }
    for word in 0..5 {
        let mut bad = c.clone();
        bad.tuple[word] += Fp::ONE;
        assert!(!bad.accepts(&public), "auxiliary tuple {word}");
    }
    let mut proposed_only = c.clone();
    proposed_only.bind_originals = false;
    assert!(proposed_only.accepts(&public));
    let known = synthesize(&proposed_only, 16, Some(&public)).unwrap();
    let unknown = synthesize(&proposed_only.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let mut overflow = proposed_only;
    overflow.values[0][1] = Fp::from(1_u64 << 32);
    assert!(!overflow.accepts(&overflow.public()));
}

#[test]
fn quota_proposals_require_complete_owners_exact_schema_and_root_only_stage() {
    let c = Claims::fixture();
    for stage in [0, 1, 2, 6, 7] {
        let mut bad = c.clone();
        bad.stage = stage;
        assert!(!bad.accepts(&bad.public()), "non-root stage {stage}");
    }
    for stage in 3..6 {
        let mut good = c.clone();
        good.stage = stage;
        assert!(good.accepts(&good.public()));
    }
    let mut short = c.clone();
    short.values.pop();
    assert!(synthesize(&short, 16, None).is_err());
    let operation = c.plan.operation().clone();
    let partition = (0..c.plan.stage_count())
        .map(|i| c.plan.q_partition(i).unwrap().to_vec())
        .collect::<Vec<_>>();
    let mut wrong = c.clone();
    wrong.plan = ContextPlan::with_schedule(
        operation.clone(),
        partition.clone(),
        Some(0),
        c.plan.object_specs().to_vec(),
    )
    .unwrap();
    assert!(
        !wrong.accepts(&wrong.public()),
        "frame-only plans cannot retain proposals"
    );
    for index in 0..6 {
        let mut specs = c.plan.object_specs().to_vec();
        specs[index].capacity += 1;
        wrong.plan =
            ContextPlan::with_schedule(operation.clone(), partition.clone(), Some(0), specs)
                .unwrap()
                .with_operation_tasks(tasks(Variant::RefreshQuotaShare))
                .unwrap();
        assert!(!wrong.accepts(&wrong.public()), "wrong capacity {index}");
    }
    for variant in VARIANTS
        .into_iter()
        .filter(|v| *v != Variant::RefreshQuotaShare)
    {
        let mut wrong = c.clone();
        wrong.originals.variant = variant;
        let policy = OwnPolicy::new([3, 4], Affine::GENERATOR).unwrap();
        let op = super::operation(
            variant,
            &RefreshStagePlan::signature_schemas(policy).unwrap(),
        );
        let groups = tasks(variant);
        let mut partition = vec![vec![0], vec![1], vec![2]];
        partition.resize_with(groups.len(), Vec::new);
        wrong.plan = ContextPlan::with_schedule(
            op,
            partition,
            Some(0),
            RefreshObjects::context_specs(variant).unwrap(),
        )
        .unwrap()
        .with_operation_tasks(groups)
        .unwrap();
        assert!(
            !wrong.accepts(&wrong.public()),
            "foreign variant {variant:?}"
        );
    }
}
