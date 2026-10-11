//! Shared framed hashing keeps exact RP57 semantics in both Pasta fields.

use iroha_pasta::{
    Fp, Fq,
    poseidon::{PoseidonField, hash_with_domain},
};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, Pow5Columns, RoundConstantColumns, SpongeChip, SpongeConfig, WordHasher,
    pow5_fq::{DuplexChip, DuplexConfig},
};

#[derive(Clone)]
struct Hashes<F: PoseidonField> {
    values: Vec<F>,
    known: bool,
}

#[derive(Clone, Debug)]
struct Config<F: PoseidonField> {
    glue: GlueConfig,
    sponge: SpongeConfig<F>,
    duplex: DuplexConfig<F>,
    public: Column<Instance>,
}

impl<F: PoseidonField> Circuit<F> for Hashes<F> {
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config<F> {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let columns = Pow5Columns::allocate(meta);
        let constants = RoundConstantColumns::allocate(meta);
        let domains: Vec<_> = (0..=6).map(|n| (123, n)).collect();
        let sponge = SpongeConfig::configure(meta, columns, constants, &domains);
        let columns = Pow5Columns::allocate(meta);
        let constants = RoundConstantColumns::allocate(meta);
        let duplex = DuplexConfig::configure(meta, columns, constants, &[]);
        let public = meta.instance_column(7);
        meta.enable_equality(public);
        Config {
            glue,
            sponge,
            duplex,
            public,
        }
    }
    fn synthesize(&self, config: Config<F>, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut sponge = SpongeChip::new(config.sponge);
        let mut duplex = DuplexChip::new(config.duplex);
        let outputs = layouter.assign_region(
            || "word hash parity",
            |mut region| {
                let values: Vec<_> = self
                    .values
                    .iter()
                    .map(|v| {
                        if self.known {
                            Value::known(*v)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect();
                let words = glue.witnesses(&mut region, &values)?;
                let mut result = Vec::new();
                for n in 0..=6 {
                    let a = WordHasher::hash_words(&mut sponge, &mut region, 123, &words[..n])?;
                    let b = WordHasher::hash_words(&mut duplex, &mut region, 123, &words[..n])?;
                    GlueChip::assert_equal(&mut region, &a, &b)?;
                    result.push(a);
                }
                duplex.absorb_constant(F::ONE);
                assert!(WordHasher::hash_words(&mut duplex, &mut region, 123, &[]).is_err());
                Ok(result)
            },
        )?;
        for (i, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

fn exercise<F: PoseidonField>() {
    let c = Hashes {
        values: vec![
            F::ZERO,
            F::ONE,
            -F::ONE,
            F::from(127),
            F::from(128),
            F::from(256),
        ],
        known: true,
    };
    let public: Vec<_> = (0..=6)
        .map(|n| hash_with_domain(123, &c.values[..n]))
        .collect();
    assert!(
        check_circuit(&c, 11, core::slice::from_ref(&public), CheckMode::Strict)
            .expect("layout")
            .is_satisfied()
    );
    let known = synthesize(&c, 11, Some(core::slice::from_ref(&public))).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 11, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    for i in 0..public.len() {
        let mut wrong = public.clone();
        wrong[i] += F::ONE;
        assert!(
            !check_circuit(&c, 11, &[wrong], CheckMode::Strict)
                .expect("forged")
                .is_satisfied()
        );
    }
}

#[test]
fn both_word_hash_backends_match_framing_padding_and_native_values() {
    exercise::<Fp>();
    exercise::<Fq>();
}
