//! Same-cell range certificate reuse, narrowing and fresh-synthesis isolation.
use super::*;
use crate::{GlueChip, GlueConfig, tamper::undetected_tampers};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::Instance,
    frontend::{Circuit, SimpleFloorPlanner, synthesize},
};

#[derive(Clone)]
struct Cached<F: PastaField> {
    value: Value<F>,
    narrow: bool,
}
impl<F: PastaField> Circuit<F> for Cached<F> {
    type Config = (GlueConfig, RunningSumConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            narrow: self.narrow,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let ports = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, ports, constants);
        let range_column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, range_column, LimbBits::new(4).unwrap());
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        (glue, range, public)
    }
    fn synthesize(
        &self,
        (glue, range, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(glue);
        let rows = SharedRows::new(RowCursor::starting_at(0));
        let mut range = RunningSumChip::with_shared_cursor(range, &rows);
        let mut other = range.clone();
        range.load_table(&mut layouter)?;
        let words = layouter.assign_region(
            || "cached exact ranges",
            |mut region| {
                let a = glue.witness(&mut region, self.value)?;
                let first = range.range_check(&mut region, &a, 3)?;
                assert_eq!(range.next_row(), 2);
                assert_eq!(other.range_check(&mut region, &a, 12)?.cell(), first.cell());
                assert_eq!(
                    range.range_check(&mut region, &first, 3)?.cell(),
                    first.cell()
                );
                assert_eq!(range.next_row(), 2);
                // The same value at a different physical cell must be checked.
                let b = range.witness_range_checked(&mut region, self.value, 3)?;
                assert_eq!(range.next_row(), 4);
                other.range_check(&mut region, &b, 12)?;
                assert_eq!(range.next_row(), 4);
                if self.narrow {
                    other.range_check(&mut region, &a, 2)?;
                    assert_eq!(range.next_row(), 6);
                }
                Ok([a, b])
            },
        )?;
        for (row, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}
fn exercise<F: PastaField>() {
    let circuit = Cached {
        value: Value::known(F::from(7)),
        narrow: false,
    };
    let public = [vec![F::from(7); 2]];
    assert!(
        check_circuit(&circuit, 7, &public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&circuit, 7, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 7, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert!(undetected_tampers(&circuit, 7, &public).unwrap().is_empty());
    // A wider certificate never discharges a new narrower request.
    let narrow = Cached {
        narrow: true,
        ..circuit.clone()
    };
    assert!(
        !check_circuit(&narrow, 7, &public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    // New synthesis gets new certificates; a modulus-adjacent alias fails.
    let alias = Cached {
        value: Value::known(-F::ONE),
        narrow: false,
    };
    assert!(
        !check_circuit(&alias, 7, &[vec![-F::ONE; 2]], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}
#[test]
fn cell_bound_range_certificates_preserve_exact_predicate_both_fields() {
    exercise::<Fp>();
    exercise::<Fq>();
}

#[derive(Clone)]
struct Banked<F: PastaField> {
    value: Value<F>,
    tagged: bool,
}
impl<F: PastaField> Circuit<F> for Banked<F> {
    type Config = (Vec<RunningSumConfig>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = bool;
    fn params(&self) -> Self::Params {
        self.tagged
    }
    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            tagged: self.tagged,
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, false)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, tagged: bool) -> Self::Config {
        let columns = (0..if tagged { 3 } else { 2 })
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>();
        let ranges = if tagged {
            assert!(RunningSumConfig::configure_tagged_bank(meta, &[]).is_empty());
            RunningSumConfig::configure_tagged_bank(meta, &columns)
        } else {
            RunningSumConfig::configure_bank(meta, &columns, LimbBits::new(4).unwrap())
        };
        assert!(RunningSumChip::<F>::banked(Vec::new()).is_err());
        assert!(RunningSumChip::<F>::banked(vec![ranges[0], ranges[0]]).is_err());
        let mut wrong = ranges.clone();
        wrong[1].table = meta.lookup_table_column();
        assert!(RunningSumChip::<F>::banked(wrong).is_err());
        if tagged {
            let mut wrong = ranges.clone();
            if let Pattern::Tagged { tag_table, .. } = &mut wrong[1].pattern {
                *tag_table = meta.lookup_table_column();
            }
            assert!(RunningSumChip::<F>::banked(wrong).is_err());
            let mut mixed = ranges.clone();
            mixed[1].pattern = Pattern::Fixed {
                step: meta.fixed_column(),
            };
            assert!(RunningSumChip::<F>::banked(mixed).is_err());
        }
        let public = meta.instance_column(10);
        meta.enable_equality(public);
        (ranges, public)
    }
    fn synthesize(
        &self,
        (ranges, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut range = RunningSumChip::banked(ranges)?;
        let mut clone = range.clone();
        range.load_table(&mut layouter)?;
        let words = layouter.assign_region(
            || "independent structural range buses",
            |mut region| {
                let mut words = Vec::new();
                for bits in [3, 4, 87, 105, 128, 3, 4, 87, 105, 128] {
                    let word = range.witness_range_checked(&mut region, self.value, bits)?;
                    let rows = range.next_row();
                    assert_eq!(
                        clone.range_check(&mut region, &word, bits)?.cell(),
                        word.cell()
                    );
                    assert_eq!(clone.next_row(), rows);
                    words.push(word);
                }
                assert!(range.next_row() < 200);
                Ok(words)
            },
        )?;
        for (row, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}
fn exercise_banks<F: PastaField>(tagged: bool) {
    let k = if tagged { 16 } else { 9 };
    let circuit = Banked {
        value: Value::known(F::from(7)),
        tagged,
    };
    let public = [vec![F::from(7); 10]];
    assert!(
        check_circuit(&circuit, k, &public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let known = synthesize(&circuit, k, Some(&public)).unwrap();
    assert_eq!(known.cs.lookups().len(), if tagged { 3 } else { 2 });
    assert!(
        known
            .cs
            .lookups()
            .iter()
            .all(|lookup| lookup.input_expressions().len() == if tagged { 2 } else { 1 })
    );
    let unknown = synthesize(&circuit.without_witnesses(), k, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert!(undetected_tampers(&circuit, k, &public).unwrap().is_empty());
    let bad = Banked {
        value: Value::known(F::from(8)),
        tagged,
    };
    assert!(
        !check_circuit(&bad, k, &[vec![F::from(8); 10]], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}
#[test]
fn banked_ranges_share_only_the_table_and_reservations_both_fields() {
    exercise_banks::<Fp>(false);
    exercise_banks::<Fq>(false);
}

#[test]
fn tagged_banks_share_exact_tuple_table_and_cell_certificates_both_fields() {
    exercise_banks::<Fp>(true);
    exercise_banks::<Fq>(true);
}
