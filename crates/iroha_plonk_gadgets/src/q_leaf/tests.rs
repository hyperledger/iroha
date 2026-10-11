//! Tests of the Q-leaf layout: the column, argument and degree counts of
//! the plan, the table and advice row ranges and the leaf capacity, the
//! chips' disjoint cursors, and the shared-table audit on honest and
//! overlapping layouts. The P-256 tests run the verifications themselves in
//! this layout (`p256::tests`, `ShaLayout::Leaf`), and the foreign-field
//! adversarial suite runs on its table (`ff::tests`).

use core::marker::PhantomData;

use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, configure, synthesize},
};

use super::*;
use crate::{
    ff::ForeignModulus,
    p256::{
        native::{FixedTable, windows},
        window::{TableSource, WindowChip},
    },
};

/// The circuit size of the leaf.
const K: u32 = 16;

/// What the audit circuit lays out after one SHA-256 block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// The leaf plan: a witness and a fixed-base decomposition of it.
    Honest,
    /// The foreign-field chip started seven rows inside the SHA-256 rows.
    FfInsideSha,
    /// The window lookups placed on the foreign-field rows.
    WindowOnFfRows,
    /// A dynamic-entry enable on the first fixed-base row (its glue advice
    /// would be added to that fixed entry).
    DynamicOnFixedRow,
    /// A valid dynamic namespace tuple in the previously empty table tail.
    DynamicRow,
    /// A tail value at the excluded 15-bit range endpoint.
    TableValueOverflow,
    /// A fixed-window tag in an inactive dynamic tail row.
    TableNamespace,
    /// A nonboolean dynamic enable beside otherwise valid dynamic metadata.
    DynamicNonboolean,
}

/// One SHA-256 block of a digest, then a scalar witness (squared once)
/// decomposed into fixed-base windows of the generator.
#[derive(Clone, Debug)]
struct AuditCircuit<F: PastaField> {
    layout: Layout,
    marker: PhantomData<F>,
}

impl<F: PastaField> AuditCircuit<F> {
    fn new(layout: Layout) -> Self {
        Self {
            layout,
            marker: PhantomData,
        }
    }
}

impl<F: PastaField> Circuit<F> for AuditCircuit<F> {
    type Config = (QLeafConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let leaf = QLeafConfig::configure(meta, advice, constants, &[]);
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        (leaf, instance)
    }

    fn synthesize(
        &self,
        (leaf, instance): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        leaf.load_tables(&mut layouter)?;
        let split = sha_rows(1);
        let QLeafChips {
            mut sha,
            ff,
            mut glue,
            ..
        } = leaf.chips::<F>(split)?;
        let mut ff = match self.layout {
            Layout::FfInsideSha => FfChip::starting_at(leaf.ff().clone(), split - 7),
            _ => ff,
        };
        // The square's fused block (with its `U` group) is the second block.
        let window_row = match self.layout {
            Layout::WindowOnFfRows => split + 7,
            _ => 0,
        };
        let mut window = WindowChip::starting_at(*leaf.p256().window(), window_row);
        let table =
            FixedTable::new(&Affine::GENERATOR, FIXED_WINDOW_BITS).ok_or(Error::Synthesis)?;
        let output = layouter.assign_region(
            || "audit",
            |mut region| {
                let q_dyn = leaf.p256().window().dynamic_column();
                let tail = leaf.p256().tables_end() + 1;
                match self.layout {
                    Layout::DynamicOnFixedRow => {
                        region.assign_fixed(q_dyn, WINDOW_TABLE_START, F::ONE)?;
                    }
                    Layout::TableValueOverflow => {
                        region.assign_fixed(
                            leaf.table().value(),
                            tail,
                            F::from(1_u64 << VALUE_BITS),
                        )?;
                    }
                    Layout::TableNamespace => {
                        region.assign_fixed(leaf.table().tag(), tail, F::ONE)?;
                    }
                    Layout::DynamicRow | Layout::DynamicNonboolean => {
                        let tag =
                            DYNAMIC_TAG_BASE + u64::try_from(tail).map_err(|_| Error::Synthesis)?;
                        region.assign_fixed(leaf.table().tag(), tail, F::from(tag))?;
                        region.assign_fixed(leaf.table().value(), tail, F::ONE)?;
                        let enable = if self.layout == Layout::DynamicRow {
                            F::ONE
                        } else {
                            F::from(2_u64)
                        };
                        region.assign_fixed(q_dyn, tail, enable)?;
                    }
                    _ => {}
                }
                let digest = glue.witness(&mut region, Value::known(F::from(5_u64)))?;
                sha.hash_digest::<Fp>(&mut region, &digest)?;
                let k = ff.witness(
                    &mut region,
                    ForeignModulus::P256_ORDER,
                    Value::known([7, 0, 0, 0]),
                )?;
                ff.square(&mut region, &k)?;
                let points = window.decompose(
                    &mut region,
                    &k,
                    &table.windows,
                    TableSource::Fixed {
                        base: 0,
                        table: &table,
                    },
                    0,
                )?;
                let (x, _) = points.first().ok_or(Error::Synthesis)?;
                Ok(x.limbs()[0].clone())
            },
        )?;
        layouter.constrain_instance(output.cell(), instance, 0)
    }
}

/// The audit verdict of a layout (on the key-generation tables: the
/// patterns are witness independent).
fn audit<F: PastaField>(layout: Layout) -> Result<(), LeafViolation> {
    let circuit = AuditCircuit::<F>::new(layout);
    let (_, (leaf, _)) = configure(&circuit).expect("configure");
    let synthesized = synthesize(&circuit, K, None).expect("synthesis");
    leaf.audit(&synthesized.tables)
}

#[test]
fn q_leaf_shape_matches_the_plan() {
    let circuit = AuditCircuit::<Fq>::new(Layout::Honest);
    let (cs, (leaf, _)) = configure(&circuit).expect("configure");
    assert_eq!(cs.num_advice_columns(), Q_LEAF_ADVICE_COLUMNS);
    assert_eq!(Q_LEAF_ADVICE_COLUMNS, 17);
    // Six `c`/`q` columns, four glue columns, the constants column and the
    // instance column: three permutation sets of four.
    assert_eq!(cs.permutation().columns().len(), 12);
    // Ten arguments: eight width-1 range arguments, the SHA-256 guest on
    // `c_0` (width 3) and the window guest on `u_0` (width 8).
    assert_eq!(cs.lookups().len(), 10);
    let mut widths: Vec<usize> = cs
        .lookups()
        .iter()
        .map(iroha_plonk::cs::LookupArgument::width)
        .collect();
    widths.sort_unstable();
    assert_eq!(widths, vec![1, 1, 1, 1, 1, 1, 1, 1, 3, 8]);
    let named = |name: &str| {
        cs.lookups()
            .iter()
            .find(|lookup| lookup.name() == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    assert_eq!(named("ff c_0 range + sha256 spread").width(), 3);
    assert_eq!(named("ff u_0 range + p256 window").width(), 8);
    for lookup in cs.lookups() {
        assert!(
            lookup.required_degree() <= crate::MAX_GATE_DEGREE,
            "{}",
            lookup.name()
        );
    }
    assert_eq!(named("ff c_0 range + sha256 spread").required_degree(), 6);
    assert_eq!(named("ff u_0 range + p256 window").required_degree(), 6);
    assert_eq!(cs.degree(), 6);
    assert_eq!(cs.blinding_factors(), 5);
    // Raw fixed columns: the shared table (8), the foreign-field patterns
    // (4), the glue coefficients (6), the constants column, the window's
    // input and dynamic-entry columns (5) and the SHA-256 tag and constant
    // columns (2); selectors come on top (compressed at key generation).
    assert_eq!(cs.num_fixed_columns(), 26);
    assert_eq!(leaf.table().columns().len(), crate::table::TABLE_COLUMNS);
    // Every advice column is queried at most three times (rotations 0, 1
    // and 6 on the operand columns, 0, 1 and 2 on the window's `z`).
    let queries = cs.advice_queries();
    for column in 0..cs.num_advice_columns() {
        let count = queries
            .iter()
            .filter(|(queried, _)| queried.index() == column)
            .count();
        assert!(count <= 3, "column {column}: {count} queries");
    }
}

/// The table rows of the plan, the 8-bit fixed-base windows (decision D5)
/// and the capacity arithmetic of the module documentation.
#[test]
fn q_leaf_rows_and_capacity() {
    assert_eq!(SHA_TABLE_START, 32_768);
    assert_eq!(WINDOW_TABLE_START, 35_201);
    assert_eq!(HASH_DIGEST_ROWS, 2_094);
    assert_eq!(sha_rows(6), 12_564);
    // 8-bit windows: 33 per base, 7,940 rows per base. Two bases (one fixed
    // key) end at 51,081, three at 59,021; five dynamic tables add 160 rows.
    assert_eq!(FIXED_WINDOW_BITS, 8);
    let generator = FixedTable::new(&Affine::GENERATOR, FIXED_WINDOW_BITS).expect("table");
    assert_eq!(generator.windows.len(), 33);
    assert_eq!(generator.rows(), 7_940);
    assert_eq!(WINDOW_TABLE_START + 2 * generator.rows(), 51_081);
    assert_eq!(WINDOW_TABLE_START + 3 * generator.rows(), 59_021);
    let usable = 65_530;
    assert!(WINDOW_TABLE_START + 3 * generator.rows() + 5 * 2 * DYNAMIC_ENTRIES <= usable);
    // Narrower windows trade table rows (free: fixed columns only) for
    // foreign-field rows: 6 bits would add 11 windows per base.
    assert_eq!(windows(6).len(), 44);
    assert_eq!(windows(7).len(), 38);
    // Capacity: 12,097 rows per witness-key verification (with its SHA
    // block) and 3,753 per fixed-key one.
    let (variable, fixed) = (2_094 + 10_003, 2_094 + 1_659);
    assert_eq!(5 * variable + fixed, 64_238);
    assert!(5 * variable + fixed <= usable);
    assert!(6 * variable > usable);
    assert!(5 * variable + 2 * fixed > usable);
}

#[test]
fn q_leaf_chips_take_disjoint_row_ranges() {
    let circuit = AuditCircuit::<Fq>::new(Layout::Honest);
    let (_, (leaf, _)) = configure(&circuit).expect("configure");
    let tables_end = leaf.p256().tables_end();
    assert_eq!(tables_end, WINDOW_TABLE_START + 7_940);
    let split = sha_rows(2);
    let chips = leaf.chips::<Fq>(split).expect("chips");
    assert_eq!(chips.sha.next_row(), 0);
    assert_eq!(chips.ff.next_row(), split);
    assert_eq!(chips.glue.next_row(), split);
    assert_eq!(chips.p256.next_window_row(), 0);
    assert_eq!(chips.p256.next_dynamic_row(), tables_end);
    // A split at the dynamic rows leaves no glue rows.
    assert!(leaf.chips::<Fq>(tables_end).is_err());
    // The dynamic cursor never starts inside the fixed tables.
    assert!(
        P256Chip::<Fq>::with_cursors(
            leaf.p256().clone(),
            RowCursor::bounded(0, split),
            RowCursor::starting_at(tables_end - 1),
        )
        .is_err()
    );
}

/// The audit accepts the leaf plan, and the honest layout checks; a
/// foreign-field block inside the SHA-256 rows and window lookups on the
/// foreign-field rows are reported (they would merge two chips' tuples in
/// one argument), and so is a dynamic-entry enable on a fixed-base row
/// (its advice would be added to the fixed entry, letting a lookup select
/// another point).
fn overlapping_layouts_case<F: PastaField>() {
    assert_eq!(audit::<F>(Layout::Honest), Ok(()));
    let circuit = AuditCircuit::<F>::new(Layout::Honest);
    // The decomposed scalar is 7: its first window's point (`x_0` on the
    // first glue row) is the public output.
    let synthesized = synthesize(&circuit, K, Some(&[vec![F::ZERO]][..])).expect("synthesis");
    let advice = synthesized.tables.advice().expect("advice");
    let glue_a = FF_ADVICE_COLUMNS + 1;
    let x0 = advice[glue_a][0];
    let report = check_circuit(&circuit, K, &[vec![x0]], CheckMode::Strict).expect("check");
    assert!(report.is_satisfied(), "{report}");
    assert!(
        !check_circuit(&circuit, K, &[vec![x0 + F::ONE]], CheckMode::Strict)
            .expect("check")
            .is_satisfied()
    );
    assert!(matches!(
        audit::<F>(Layout::FfInsideSha),
        Err(LeafViolation::ShaOverlap { .. })
    ));
    assert!(matches!(
        audit::<F>(Layout::WindowOnFfRows),
        Err(LeafViolation::WindowOverlap { .. })
    ));
    assert_eq!(
        audit::<F>(Layout::DynamicOnFixedRow),
        Err(LeafViolation::DynamicEnable {
            row: WINDOW_TABLE_START
        })
    );
}

#[test]
fn q_leaf_audit_rejects_overlapping_layouts() {
    overlapping_layouts_case::<Fp>();
    overlapping_layouts_case::<Fq>();
}

/// The audit checks fixed construction metadata, not the dynamic advice copies
/// or proof soundness. These tail assignments deliberately bypass the chip's
/// table producer so each missing audit rejection branch can be isolated.
fn malformed_table_tail_case<F: PastaField>() {
    let circuit = AuditCircuit::<F>::new(Layout::Honest);
    let (cs, (leaf, _)) = configure(&circuit).expect("configure");
    let row = leaf.p256().tables_end() + 1;
    assert!(row < cs.usable_rows(K).expect("usable rows"));
    assert_eq!(audit::<F>(Layout::Honest), Ok(()));
    assert_eq!(audit::<F>(Layout::DynamicRow), Ok(()));
    assert_eq!(
        audit::<F>(Layout::TableValueOverflow),
        Err(LeafViolation::ValueRange { row })
    );
    assert_eq!(
        audit::<F>(Layout::TableNamespace),
        Err(LeafViolation::Namespace { row })
    );
    assert_eq!(
        audit::<F>(Layout::DynamicNonboolean),
        Err(LeafViolation::DynamicEnable { row })
    );
}

#[test]
fn q_leaf_audit_rejects_malformed_table_tail_both_fields() {
    malformed_table_tail_case::<Fp>();
    malformed_table_tail_case::<Fq>();
}
