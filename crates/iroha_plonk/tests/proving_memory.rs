//! Every byte witness synthesis and proving allocate, against `peak_proving_columns`.
//!
//! A counting global allocator records the live heap. One circuit with advice, fixed, lookup
//! and copy columns is keyed with no coset cache, as the wallet reads its keys, then each case
//! measures from before witness synthesis to the end of the owned-witness proof, fused and in
//! bounded passes. The peak above the starting heap, less the MSM scratch the process budget
//! reports, must fit the counted `proof` columns and use most of them. This is the only test
//! in this binary, so no other test's allocations are counted.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use iroha_pasta::{Ep, PastaField, msm::SharedMemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned,
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector, TableColumn, TranscriptV1},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    keys::{CosetCachePolicy, KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prover::peak_proving_columns,
    verify_full,
};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

struct Counting;

#[global_allocator]
static ALLOCATOR: Counting = Counting;

// SAFETY: every request is forwarded unchanged to System; only successful requests and
// releases adjust the counters, which never allocate.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's valid layout, unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's valid layout, unchanged.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` came from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `pointer` came from System with this layout; the caller's new size.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        moved
    }
}

const K: u32 = 14;
const ADVICE: usize = 8;

#[derive(Clone, Copy, Debug)]
struct Config {
    advice: [Column<Advice>; ADVICE],
    fixed: Column<Fixed>,
    gate: Selector,
    range: Selector,
    table: TableColumn,
}

/// Rows of `a0 a1 a2 = a3`, `a4 = f`, `a5 + a6 = a7`, with `a0`, `a1` and `a2` looked up in
/// `0..6` and `a5` copying the previous row's `a0`.
#[derive(Clone, Debug)]
struct Wide {
    rows: usize,
}

impl<F: PastaField> Circuit<F> for Wide {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let fixed = meta.fixed_column();
        for column in [advice[0], advice[4], advice[5], advice[6]] {
            meta.enable_equality(column);
        }
        let gate = meta.selector();
        let range = meta.complex_selector();
        let table = meta.lookup_table_column();
        meta.create_gate("rows", |cells| {
            let enabled = cells.query_selector(gate);
            let a = advice.map(|column| cells.query_advice(column, Rotation::cur()));
            let f = cells.query_fixed(fixed, Rotation::cur());
            vec![
                enabled.clone() * (a[0].clone() * a[1].clone() * a[2].clone() - a[3].clone()),
                enabled.clone() * (a[4].clone() - f),
                enabled * (a[5].clone() + a[6].clone() - a[7].clone()),
            ]
        });
        for index in 0..3 {
            meta.lookup(format!("range {index}"), |cells| {
                let enabled = cells.query_selector(range);
                let value = cells.query_advice(advice[index], Rotation::cur());
                vec![(enabled * value, table)]
            });
        }
        Config {
            advice,
            fixed,
            gate,
            range,
            table,
        }
    }

    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "digits",
            |mut table| {
                for value in 0..6_u64 {
                    let row = usize::try_from(value).map_err(|_| Error::Synthesis)?;
                    table.assign_cell(
                        || "d",
                        config.table,
                        row,
                        || Value::known(F::from(value)),
                    )?;
                }
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "rows",
            |mut region| {
                let mut previous = None;
                for row in 0..self.rows {
                    let index = u64::try_from(row).map_err(|_| Error::Synthesis)?;
                    let digits = [index % 6, index / 6 % 6, index / 36 % 6];
                    let carried = previous.map_or(0, |(value, _)| value);
                    let values = [
                        digits[0],
                        digits[1],
                        digits[2],
                        digits[0] * digits[1] * digits[2],
                        index,
                        carried,
                        index,
                        carried + index,
                    ];
                    config.gate.enable(&mut region, row)?;
                    region.enable_selector(|| "range", &config.range, row)?;
                    region.assign_fixed(config.fixed, row, F::from(index))?;
                    let mut cells = Vec::with_capacity(ADVICE);
                    for (column, value) in config.advice.iter().zip(values) {
                        cells.push(region.assign_advice(
                            *column,
                            row,
                            Value::known(F::from(value)),
                        )?);
                    }
                    if let Some((_, cell)) = previous {
                        region.constrain_equal(cells[5].cell(), cell)?;
                    }
                    previous = Some((digits[0], cells[0].cell()));
                }
                Ok(())
            },
        )
    }
}

#[test]
fn synthesis_and_proving_fit_the_counted_columns() {
    let circuit = Wide {
        rows: (1 << K) - 64,
    };
    let params = PinnedParams::<Ep>::derive(K).expect("params");
    let mut config = KeygenConfig::new(TranscriptV1::Blake2bChallenge255);
    config.coset_cache = CosetCachePolicy::OnDemand;
    let before_key = LIVE.load(Ordering::Relaxed);
    let pk = keygen_pk(&params, &circuit, &config).expect("proving key");
    let key_bytes = LIVE.load(Ordering::Relaxed) - before_key;
    let column = (1_usize << K) * size_of::<<Ep as iroha_pasta::PastaCurve>::ScalarExt>();
    let descriptor = pk.binding().descriptor();
    let fused = peak_proving_columns(descriptor, None).expect("columns");
    // The key holds at least every column counted for it.
    assert!(
        key_bytes >= fused.key * column,
        "{key_bytes} < {}",
        fused.key * column
    );
    let instances: Vec<Vec<_>> = Vec::new();
    for quotient_columns in [None, Some(4), Some(16)] {
        let counted = peak_proving_columns(descriptor, quotient_columns).expect("columns");
        assert_eq!(counted.key, fused.key);
        let start = LIVE.load(Ordering::Relaxed);
        PEAK.store(start, Ordering::Relaxed);
        let witness = Witness::from_circuit(&pk, &circuit, &instances).expect("witness");
        let proof = create_proof_owned(
            &params,
            &pk,
            witness,
            ProverRandomness::os(),
            ProverConfig {
                quotient_columns,
                ..ProverConfig::default()
            },
        )
        .expect("proof");
        let measured = PEAK.load(Ordering::Relaxed) - start;
        let scratch = SharedMemoryBudget::process_default().peak_bytes();
        let bound = counted.proof * column;
        eprintln!(
            "PROVING_MEMORY quotient_columns={quotient_columns:?} counted_columns={} \
             counted_bytes={bound} measured_bytes={measured} msm_scratch_peak={scratch} \
             key_columns={} key_bytes={key_bytes}",
            counted.proof, counted.key
        );
        assert!(
            measured <= bound + scratch,
            "{quotient_columns:?}: measured {measured} > counted {bound} + scratch {scratch}"
        );
        // Tight: the count stays within an eighth above what proving held without scratch.
        assert!(
            bound <= measured + measured / 8,
            "{quotient_columns:?}: counted {bound} far above measured {measured}"
        );
        assert_eq!(
            verify_full(
                &params,
                pk.binding(),
                pk.vk(),
                &instances,
                &proof,
                iroha_pasta::msm::MemoryBudget::DEFAULT
            ),
            Ok(())
        );
    }
}
