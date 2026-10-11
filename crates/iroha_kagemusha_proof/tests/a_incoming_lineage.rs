//! Total incoming lineage widths, preserved originals and fixed arithmetic dummy.

#[path = "a_incoming_lineage/tape.rs"]
mod tape;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::a_relation::IncomingLineageCells;
use iroha_pasta::Fp;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, RunningSumChip, RunningSumConfig, UintChip,
};

#[derive(Clone, Debug)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Incoming {
    fields: [Fp; 18],
    encoding: bool,
    known: bool,
}
impl Circuit<Fp> for Incoming {
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
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constant = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constant);
        let advice = meta.advice_column();
        let range = RunningSumConfig::configure(meta, advice, LimbBits::new(9).unwrap());
        let public = meta.instance_column(37);
        meta.enable_equality(public);
        Config {
            glue,
            range,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "total incoming public prefix",
            |mut region| {
                let fields = self.fields.map(|v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                });
                let fields = glue
                    .witnesses(&mut region, &fields)?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let encoding = glue.witness(
                    &mut region,
                    if self.known {
                        Value::known(Fp::from(u64::from(self.encoding)))
                    } else {
                        Value::unknown()
                    },
                )?;
                let encoding = glue.assert_bool(&mut region, &encoding)?;
                let incoming = IncomingLineageCells::constrain(
                    &mut UintChip::new(&mut glue, &mut range),
                    &mut region,
                    &fields,
                    &encoding,
                )?;
                assert!(incoming.carrier().is_err());
                GlueChip::assert_equal(
                    &mut region,
                    incoming.omega_key_digest(),
                    &incoming.fields()[17],
                )?;
                let mut out = incoming.fields().to_vec();
                out.extend(incoming.checked().fields().iter().cloned());
                out.push(incoming.valid().word().clone());
                Ok(out)
            },
        )?;
        for (i, v) in out.iter().enumerate() {
            layouter.constrain_instance(v.cell(), config.public, i)?;
        }
        Ok(())
    }
}
impl Incoming {
    fn public(&self, valid: bool) -> Vec<Vec<Fp>> {
        let mut out = self.fields.to_vec();
        if valid {
            out.extend(self.fields);
        } else {
            out.push(Fp::ONE);
            out.extend([Fp::ZERO; 17]);
        }
        out.push(Fp::from(u64::from(valid)));
        vec![out]
    }
}
#[test]
fn malformed_lineage_preserves_originals_and_selects_fixed_dummy() {
    let mut fields = [Fp::ONE; 18];
    fields[13] = Fp::from_u128((1u128 << 104) - 1);
    fields[14] = Fp::from_u128(u128::MAX);
    let source = Incoming {
        fields,
        encoding: true,
        known: true,
    };
    assert!(
        check_circuit(&source, 14, &source.public(true), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    for index in [0, 1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 13, 14, 18] {
        let mut bad = source.clone();
        match index {
            0 => bad.fields[0] = Fp::from(2),
            13 => bad.fields[13] = Fp::from_u128(1u128 << 104),
            18 => bad.encoding = false,
            _ => bad.fields[index] = Fp::from(2).pow_vartime([128]),
        }
        assert!(
            check_circuit(&bad, 14, &bad.public(false), CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "total malformed index{index}"
        );
        assert!(
            !check_circuit(&bad, 14, &bad.public(true), CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "forged true index{index}"
        );
        if index != 18 {
            let mut forged = bad.public(false);
            forged[0][index] = source.fields[index];
            assert!(
                !check_circuit(&bad, 14, &forged, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "original field{index} replaced"
            );
        }
    }
    let mut modulus = source.clone();
    modulus.fields[1] = -Fp::ONE;
    assert!(
        check_circuit(&modulus, 14, &modulus.public(false), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&source, 14, None).unwrap();
    let unknown = synthesize(&source.without_witnesses(), 14, None).unwrap();
    let malformed = synthesize(&modulus, 14, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.tables.fixed(), malformed.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        malformed.tables.advice_assigned()
    );
    let rows = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!("total incoming lineage rows={rows:?}");
}
