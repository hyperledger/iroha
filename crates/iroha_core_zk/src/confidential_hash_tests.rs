//! Native host/chip parity for every confidential Poseidon domain on both fields.
use iroha_pasta::{Fp, Fq, poseidon::PoseidonField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    AbsorbInput, GlueChip, GlueConfig, Pow5Columns, RoundConstantColumns, SpongeChip, SpongeConfig,
};
use std::marker::PhantomData;
fn domains() -> [(u64, &'static [u64]); 7] {
    [
        (super::CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3, &[3, 5]),
        (super::CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3, &[3, 5, 8, 13]),
        (
            super::CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
            &[3, 5, 8, 13],
        ),
        (super::CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, &[3]),
        (super::CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3, &[3, 5]),
        (super::CONFIDENTIAL_POSEIDON_ASSET_DOMAIN_V3, &[3]),
        (super::CONFIDENTIAL_POSEIDON_NETWORK_DOMAIN_V3, &[3]),
    ]
}
#[derive(Clone)]
struct Config<F> {
    glue: GlueConfig,
    hash: SpongeConfig<F>,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Hashes<F> {
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PoseidonField> Circuit<F> for Hashes<F> {
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            marker: PhantomData,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constant = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constant);
        let lane = Pow5Columns::allocate(meta);
        let rc = RoundConstantColumns::allocate(meta);
        let hash = SpongeConfig::configure(meta, lane, rc, &[]);
        let public = meta.instance_column(7);
        meta.enable_equality(public);
        Config { glue, hash, public }
    }
    fn synthesize(&self, config: Config<F>, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut hash = SpongeChip::new(config.hash);
        let values = layouter.assign_region(
            || "confidential hash domains",
            |mut region| {
                domains()
                    .iter()
                    .map(|(domain, inputs)| {
                        let words = inputs
                            .iter()
                            .map(|input| {
                                glue.witness(
                                    &mut region,
                                    if self.known {
                                        Value::known(F::from(*input))
                                    } else {
                                        Value::unknown()
                                    },
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        let items = words.iter().map(AbsorbInput::Word).collect::<Vec<_>>();
                        hash.hash(&mut region, *domain, &items)
                    })
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        for (row, value) in values.iter().enumerate() {
            layouter.constrain_instance(value.cell(), config.public, row)?;
        }
        Ok(())
    }
}
fn check<F: PoseidonField>() {
    let expected = domains()
        .iter()
        .map(|(domain, inputs)| {
            super::confidential_poseidon_hash_v3(
                *domain,
                &inputs.iter().copied().map(F::from).collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert!(expected.iter().all(|value| *value != F::ZERO));
    let public = vec![expected];
    let circuit = Hashes::<F> {
        known: true,
        marker: PhantomData,
    };
    assert!(
        check_circuit(&circuit, 11, &public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    for row in 0..7 {
        let mut wrong = public.clone();
        wrong[0][row] += F::ONE;
        assert!(
            !check_circuit(&circuit, 11, &wrong, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    let known = synthesize(&circuit, 11, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 11, None).unwrap();
    assert_eq!(known.cs, unknown.cs);
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
#[test]
fn secure_confidential_poseidon_host_and_chip_match_all_domains_on_both_pasta_fields() {
    check::<Fp>();
    check::<Fq>();
}
