//! Raw 256-bit bridge boundary and every-cell binding checks.

use super::*;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::{configure, synthesize},
};
use iroha_plonk_gadgets::{
    GlueConfig,
    ff::{FfChip, FfConfig},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};
use rayon::prelude::*;

#[derive(Clone)]
struct Bridge {
    raw: [u64; 4],
    known: bool,
}
impl Circuit<Fq> for Bridge {
    type Config = (FfConfig, GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let cols = core::array::from_fn(|_| meta.advice_column());
        let ff = FfConfig::configure(meta, cols, &[ForeignModulus::P256_BASE]);
        let cols = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, cols, constants);
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        (ff, glue, public)
    }
    fn synthesize(
        &self,
        (config, glue, public): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let mut ff = FfChip::new(config);
        ff.load_table(&mut layouter)?;
        let mut glue = GlueChip::new(glue);
        let output = layouter.assign_region(
            || "raw bridge",
            |mut region| {
                let value = if self.known {
                    Value::known(self.raw)
                } else {
                    Value::unknown()
                };
                let input = ff.witness(&mut region, ForeignModulus::P256_BASE, value)?;
                export_raw(&mut glue, &mut region, &input)
            },
        )?;
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}
fn inputs(raw: [u64; 4]) -> [Vec<Fq>; 1] {
    let n = Nat::from_words(raw);
    [vec![
        Fq::from_u128(n.low_u128()),
        Fq::from_u128(n.shr(128).low_u128()),
    ]]
}

#[test]
fn raw_bridge_full_width_and_every_cell_are_bound() {
    for n in [
        Nat::ZERO,
        Nat::pow2(128).wrapping_sub(&Nat::ONE),
        Nat::pow2(128),
        Nat::pow2(255),
        Nat::pow2(256).wrapping_sub(&Nat::ONE),
        ForeignModulus::P256_BASE.nat(),
    ] {
        let c = Bridge {
            raw: n.low_words(),
            known: true,
        };
        let public = inputs(c.raw);
        assert!(
            check_circuit(&c, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    let c = Bridge {
        raw: [u64::MAX; 4],
        known: true,
    };
    let public = inputs(c.raw);
    let known = synthesize(&c, 16, Some(&public)).unwrap();
    let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let cells = assigned_advice_cells(&c, 16, &public).unwrap();
    assert!(!cells.is_empty());
    let misses: Vec<_> = cells
        .par_iter()
        .filter_map(|&(column, row)| {
            let result = check_tampered(
                &c,
                16,
                &public,
                Some(Tamper {
                    column,
                    row,
                    delta: Fq::ONE,
                }),
            )
            .unwrap();
            result.is_satisfied().then_some((column, row))
        })
        .collect();
    assert!(misses.is_empty(), "{misses:?}");
}
#[test]
fn signature_leaf_keeps_shared_table_admission() {
    let slot = SignatureSlot {
        mode: VerifyMode::Soft,
        key: SignatureKey::Variable,
    };
    let c = QSignatureCircuit::new(
        QSignaturePlan::new(vec![slot]).unwrap(),
        vec![SignatureWitness {
            digest: Fp::ONE,
            key: [[u64::MAX; 4]; 2],
            signature: [[u64::MAX; 4]; 2],
        }],
    )
    .unwrap();
    let public = c.instances(&[false]).unwrap();
    let (_, config) = configure(&c).unwrap();
    for snapshot in [
        synthesize(&c, 16, Some(&public)).unwrap(),
        synthesize(&c.without_witnesses(), 16, None).unwrap(),
    ] {
        assert_eq!(config.leaf.audit(&snapshot.tables), Ok(()));
    }
}
