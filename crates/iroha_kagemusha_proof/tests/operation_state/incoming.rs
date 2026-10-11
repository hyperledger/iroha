//! Differential total incoming semantics and rejected-value digest preservation.

use super::*;
use iroha_kagemusha_proof::operation_relation::incoming_statement::{
    DynamicStatementCells, IncomingStatementCells, StatementView,
};

#[derive(Clone)]
struct Incoming {
    statement: StatementCircuit,
    valid: bool,
    dynamic: bool,
}
impl Circuit<Fp> for Incoming {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            statement: self.statement.without_witnesses(),
            valid: self.valid,
            dynamic: self.dynamic,
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        configure_columns(meta, 28)
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(c.glue);
        let mut range = RunningSumChip::new(c.range);
        let mut hash = SpongeChip::new(c.sponge);
        range.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "total statement",
            |mut region| {
                let fields = glue
                    .witnesses(
                        &mut region,
                        &self
                            .statement
                            .fields
                            .iter()
                            .map(|v| {
                                if self.statement.known {
                                    Value::known(*v)
                                } else {
                                    Value::unknown()
                                }
                            })
                            .collect::<Vec<_>>(),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                if self.dynamic {
                    let statement = DynamicStatementCells::constrain(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        &fields,
                    )?;
                    let mut output = statement.fields().to_vec();
                    output.push(statement.digest().clone());
                    output.push(statement.valid().word().clone());
                    return Ok(output);
                }
                let statement = IncomingStatementCells::constrain(
                    &mut uint,
                    &mut hash,
                    &mut region,
                    self.statement.variant,
                    &fields,
                )?;
                statement.integer::<128>(&mut uint, &mut region, 9)?;
                assert!(
                    statement.integer::<64>(&mut uint, &mut region, 9).is_err(),
                    "fixed width cannot be relabeled"
                );
                let mut output = statement.fields().to_vec();
                output.push(statement.digest().clone());
                output.push(statement.valid().word().clone());
                Ok(output)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}
impl Incoming {
    fn public(&self) -> Vec<Fp> {
        let mut p = self.statement.public();
        p.push(Fp::from(u64::from(self.valid)));
        p
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 12, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}
#[test]
fn all_incoming_statement_variants_match_hard_semantics_and_preserve_rejected_words() {
    for variant in Variant::ALL {
        let c = Incoming {
            statement: statement(variant),
            valid: true,
            dynamic: false,
        };
        assert!(c.accepts(), "{variant:?}");
        let known = synthesize(&c, 12, Some(&[c.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        for index in 0..26 {
            let mut wrong = c.clone();
            wrong.statement.fields[index] = -Fp::ONE;
            wrong.valid = wrong.statement.accepts();
            assert!(
                wrong.accepts(),
                "total {variant:?} field{index}, expected{}",
                wrong.valid
            );
            wrong.valid = !wrong.valid;
            assert!(!wrong.accepts(), "false verdict {variant:?} field{index}");
        }
    }
}
#[test]
fn incoming_statement_range_boundaries_cannot_alias_or_hide_burn_predicate() {
    let c = Incoming {
        statement: statement(Variant::Send),
        valid: true,
        dynamic: false,
    };
    for (index, value) in [
        (0, Fp::from(1 << 16)),
        (8, Fp::from(256)),
        (11, Fp::from(8)),
        (9, Fp::from_u128(1 << 127).double()),
        (20, Fp::from_u128(1 << 127).double()),
        (24, Fp::from_u128(1 << 64)),
        (25, Fp::from_u128(1 << 64)),
        (21, Fp::from_u128(u128::MAX)),
        (22, Fp::from_u128(u128::MAX)),
    ] {
        let mut wrong = c.clone();
        wrong.statement.fields[index] = value;
        wrong.valid = false;
        assert!(wrong.accepts(), "total boundary {index}");
        let mut digest_alias = wrong.public();
        let mut reduced = wrong.statement.fields;
        reduced[index] = Fp::ZERO;
        digest_alias[26] = hash_with_domain(STATEMENT_DOMAIN, &reduced);
        assert!(
            !check_circuit(&wrong, 12, &[digest_alias], CheckMode::Strict)
                .expect("alias layout")
                .is_satisfied()
        );
        wrong.valid = true;
        assert!(!wrong.accepts(), "boundary true {index}");
    }
}

#[test]
fn dynamic_status_head_uses_one_layout_for_all_operations_and_total_invalid_tags() {
    let mut layout = None;
    for variant in Variant::ALL {
        let c = Incoming {
            statement: statement(variant),
            valid: true,
            dynamic: true,
        };
        assert!(c.accepts(), "dynamic {variant:?}");
        let known = synthesize(&c, 12, Some(&[c.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        if let Some((fixed, permutation)) = &layout {
            assert_eq!(
                known.tables.fixed(),
                fixed,
                "witness tag cannot change constants"
            );
            assert_eq!(
                known.tables.permutation(),
                permutation,
                "witness tag cannot change copies"
            );
        } else {
            layout = Some((
                known.tables.fixed().to_vec(),
                known.tables.permutation().clone(),
            ));
        }
        for i in 0..26 {
            let mut wrong = c.clone();
            wrong.statement.fields[i] = -Fp::ONE;
            wrong.valid = wrong.statement.accepts();
            assert!(wrong.accepts(), "dynamic total {variant:?} field{i}");
            wrong.valid = !wrong.valid;
            assert!(!wrong.accepts(), "forged dynamic {variant:?} field{i}");
        }
        for tag in [0, 9, 255, 256] {
            let mut wrong = c.clone();
            wrong.statement.fields[16] = Fp::from(tag);
            wrong.valid = false;
            assert!(wrong.accepts());
            wrong.valid = true;
            assert!(!wrong.accepts());
        }
    }
}
