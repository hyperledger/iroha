//! Native parity, coordinated arbitrary-field mutations and real IPA controls.

use super::*;
use crate::ram_lfe_test_support::NativeProof;
use iroha_plonk::{
    check::{CheckFailure, CheckMode, CheckReport, check_circuit},
    cs::Instance,
    frontend::{Circuit, SimpleFloorPlanner},
};
use std::{cell::RefCell, sync::Arc, time::Instant};

thread_local! {
    static CLEARED: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    static INPUTS_CLEARED: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn observe_work_clear(zero: bool) {
    CLEARED.with(|values| values.borrow_mut().push(zero));
}

struct Inputs<const L: usize>([[u8; 32]; L]);

impl<const L: usize> Drop for Inputs<L> {
    fn drop(&mut self) {
        self.0.zeroize();
        INPUTS_CLEARED.with(|values| {
            values
                .borrow_mut()
                .push(self.0.iter().flatten().all(|byte| *byte == 0))
        });
    }
}

#[derive(Clone)]
struct HashCircuit<F: PastaField, const L: usize> {
    values: Arc<Inputs<L>>,
    faults: Vec<Fault<F>>,
    bind_output: bool,
    stop: Stop,
}

impl<F: PastaField, const L: usize> HashCircuit<F, L> {
    fn new(values: [F; L]) -> Self {
        Self {
            values: Arc::new(Inputs(values.map(|value| value.to_repr()))),
            faults: Vec::new(),
            bind_output: true,
            stop: Stop::None,
        }
    }

    fn expected(&self) -> Vec<F> {
        if self.bind_output {
            vec![
                Option::from(F::from_repr(F::native_hash(&self.values.0)))
                    .expect("native canonical output"),
            ]
        } else {
            Vec::new()
        }
    }

    fn preflight(k: u32) -> Result<(), Error> {
        if L == 0 || L > MAX_FIELDS {
            return Err(Error::Synthesis);
        }
        let mut meta = ConstraintSystem::<F>::default();
        let _ = Self::configure(&mut meta);
        // Source cells have explicit disjoint absolute rows after the hash.
        // Preflight the bounded layout before any domain-sized allocation;
        let required = hash_rows(L) + L + meta.minimum_rows();
        if 1_usize.checked_shl(k).is_none_or(|rows| rows < required) {
            return Err(Error::NotEnoughRowsAvailable { current_k: k });
        }
        Ok(())
    }

    fn check(&self, k: u32, instances: Vec<Vec<F>>) -> Result<CheckReport<F>, Error> {
        Self::preflight(k)?;
        check_circuit(self, k, &instances, CheckMode::Strict)
    }
}

impl<F: PastaField, const L: usize> Circuit<F> for HashCircuit<F, L> {
    type Config = (PoseidonConfig<F>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = bool;

    fn params(&self) -> bool {
        self.bind_output
    }

    fn without_witnesses(&self) -> Self {
        let mut empty = Self::new([F::ZERO; L]);
        empty.bind_output = self.bind_output;
        empty
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, true)
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, bind_output: bool) -> Self::Config {
        let config = PoseidonConfig::configure(meta);
        let instance = meta.instance_column(usize::from(bind_output));
        meta.enable_equality(instance);
        (config, instance)
    }

    fn synthesize(
        &self,
        (config, instance): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        if L == 0 || L > MAX_FIELDS {
            return Err(Error::Synthesis);
        }
        let inputs: [Cell; L] = layouter.assign_region(
            || "original private input cells",
            |mut region| {
                let mut cells = Vec::with_capacity(L);
                for index in 0..L {
                    let value: F = Option::from(F::from_repr(self.values.0[index]))
                        .expect("owned canonical input");
                    // Sources occupy disjoint absolute rows after the hash.
                    cells.push(
                        region
                            .assign_advice(
                                config.input[0],
                                hash_rows(L) + index,
                                Value::known(value),
                            )?
                            .cell(),
                    );
                }
                Ok(cells.try_into().expect("exact input count"))
            },
        )?;
        let output = hash(
            &config,
            &mut layouter,
            &inputs,
            &self.values.0,
            &self.faults,
            self.stop,
        )?;
        if self.bind_output {
            layouter.constrain_instance(output, instance, 0)?;
        }
        Ok(())
    }
}

fn assert_valid<F: PastaField, const L: usize>(values: [F; L], k: u32) {
    let circuit = HashCircuit::new(values);
    circuit
        .check(k, vec![circuit.expected()])
        .expect("bounded shape")
        .into_result()
        .expect("all constraints hold");
}

#[test]
fn every_upstream_hash_vector_matches_both_field_circuits() {
    fn check<F: PastaField>(bytes: &[u8]) {
        assert_eq!(bytes.len(), 11 * 96);
        for case in bytes.chunks_exact(96) {
            let values = std::array::from_fn(|i| {
                Option::from(F::from_repr(case[i * 32..(i + 1) * 32].try_into().unwrap())).unwrap()
            });
            let expected = Option::from(F::from_repr(case[64..].try_into().unwrap())).unwrap();
            let circuit = HashCircuit::<F, 2>::new(values);
            assert_eq!(circuit.expected(), vec![expected]);
            circuit
                .check(7, vec![vec![expected]])
                .unwrap()
                .into_result()
                .expect("all constraints hold");
        }
    }
    check::<Fp>(include_bytes!(
        "../../iroha_zkp_poseidon/src/pasta/fp_hash_kats.bin"
    ));
    check::<Fq>(include_bytes!(
        "../../iroha_zkp_poseidon/src/pasta/fq_hash_kats.bin"
    ));
}

#[test]
fn odd_even_lengths_match_native_and_reject_wrong_public_output() {
    fn check<F: PastaField>() {
        assert_valid([F::ZERO], 7);
        assert_valid([-F::ONE, F::ONE], 7);
        assert_valid([F::ONE, F::ZERO, -F::ONE], 8);
        assert_valid([F::ONE; 4], 8);
        assert_valid([F::ONE; 5], 8);
        assert_valid(std::array::from_fn::<_, 22, _>(|i| F::from(i as u64)), 10);
        assert_valid([F::ZERO; 262], 14);
        let circuit = HashCircuit::new([F::ONE; 3]);
        let mut public = circuit.expected();
        public[0] += F::ONE;
        assert!(
            circuit
                .check(8, vec![public])
                .unwrap()
                .into_result()
                .is_err()
        );
    }
    check::<Fp>();
    check::<Fq>();
}

fn failures<F: PastaField>(fault: Fault<F>) -> Vec<CheckFailure<F>> {
    let label = format!("coordinated mutation must fail without an output binding: {fault:?}");
    let mut circuit = HashCircuit::new([F::from(3), F::from(7), F::from(11)]);
    circuit.bind_output = false;
    circuit.faults.push(fault);
    circuit
        .check(8, vec![Vec::new()])
        .unwrap()
        .into_result()
        .expect_err(&label)
}

#[test]
fn every_round_rejects_propagated_arbitrary_field_changes_without_output_checks() {
    fn check<F: PastaField>() {
        let half = Option::<F>::from(F::from(2).invert()).unwrap();
        for block in 0..2 {
            for round_row in 0..ROUND_ROWS {
                for column in 0..3 {
                    let rejected = failures(Fault::State {
                        row: block * (ROUND_ROWS + 1) + round_row + 2,
                        column,
                        value: half,
                    });
                    assert!(rejected.iter().all(|failure| matches!(
                        failure,
                        CheckFailure::ConstraintNotSatisfied { .. }
                    )));
                }
            }
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn every_paired_first_sbox_rejects_propagated_fractions_without_output_checks() {
    fn check<F: PastaField>() {
        let half = Option::<F>::from(F::from(2).invert()).unwrap();
        for block in 0..2 {
            for pair in 0..28 {
                let rejected = failures(Fault::PartialSbox {
                    row: block * (ROUND_ROWS + 1) + 5 + pair,
                    value: half,
                });
                assert!(
                    rejected.iter().all(|failure| matches!(
                        failure,
                        CheckFailure::ConstraintNotSatisfied { .. }
                    ))
                );
            }
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn initial_absorption_copy_and_padding_constraints_reject_coordinated_fractions() {
    fn check<F: PastaField>() {
        let half = Option::<F>::from(F::from(2).invert()).unwrap();
        for column in 0..3 {
            let rejected = failures(Fault::State {
                row: 0,
                column,
                value: half,
            });
            assert!(
                rejected
                    .iter()
                    .all(|failure| matches!(failure, CheckFailure::ConstraintNotSatisfied { .. }))
            );
        }
        for row in [1, ROUND_ROWS + 2] {
            for column in 0..3 {
                failures(Fault::<F>::State {
                    row,
                    column,
                    value: half,
                });
            }
        }
        for index in 0..3 {
            for fault in [
                Fault::Input { index, value: half },
                Fault::Copy {
                    index,
                    source: (index + 1) % 3,
                },
            ] {
                let rejected = failures(fault);
                assert!(
                    rejected
                        .iter()
                        .all(|failure| matches!(failure, CheckFailure::CopyMismatch { .. }))
                );
            }
        }
        let rejected = failures(Fault::Padding(half));
        assert!(
            rejected
                .iter()
                .all(|failure| matches!(failure, CheckFailure::ConstraintNotSatisfied { .. }))
        );
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn actual_owned_field_and_input_cells_clear_on_success_error_and_unwind() {
    fn check<F: PastaField>() {
        for stop in [
            Stop::None,
            Stop::ErrorAfterAbsorb,
            Stop::PanicAfterAbsorb,
            Stop::ErrorAfterPartialSbox,
            Stop::PanicAfterPartialSbox,
        ] {
            CLEARED.with(|values| values.borrow_mut().clear());
            INPUTS_CLEARED.with(|values| values.borrow_mut().clear());
            let outcome = std::panic::catch_unwind(|| {
                let mut circuit = HashCircuit::new([F::ONE; 3]);
                circuit.stop = stop;
                circuit.check(8, vec![circuit.expected()])
            });
            if matches!(stop, Stop::PanicAfterAbsorb | Stop::PanicAfterPartialSbox) {
                assert!(outcome.is_err());
            } else if matches!(stop, Stop::ErrorAfterAbsorb | Stop::ErrorAfterPartialSbox) {
                assert!(outcome.unwrap().is_err());
            } else {
                outcome
                    .unwrap()
                    .unwrap()
                    .into_result()
                    .expect("all constraints hold");
            }
            for observed in [&CLEARED, &INPUTS_CLEARED] {
                observed.with(|values| {
                    let values = values.borrow();
                    assert!(!values.is_empty());
                    assert!(values.iter().all(|value| *value));
                });
            }
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn geometry_and_fixed_bounds_are_explicit() {
    let mut meta = ConstraintSystem::<Fp>::default();
    let _ = HashCircuit::<Fp, 3>::configure(&mut meta);
    assert_eq!(meta.degree(), 6);
    assert_eq!(meta.num_advice_columns(), 5);
    assert_eq!(meta.advice_queries().len(), 8);
    assert_eq!(meta.lookups().len(), 0);
    assert_eq!(meta.permutation().columns().len(), 6);
    assert_eq!(meta.num_fixed_columns(), 6);
    assert_eq!(meta.fixed_queries().len(), 6);
    assert_eq!(hash_rows(3), 75);
    assert_eq!(hash_rows(2054), 38000);
    assert!(
        hash_rows(MAX_FIELDS) + MAX_FIELDS + meta.minimum_rows() <= 1 << 16,
        "maximum record and source copies fit the default k"
    );
    assert!(
        HashCircuit::<Fp, 0>::new([])
            .check(8, vec![Vec::new()])
            .is_err()
    );
    assert!(
        HashCircuit::<Fp, 2055>::new([Fp::ZERO; 2055])
            .check(8, vec![Vec::new()])
            .is_err()
    );
    println!(
        "RAM_LFE_POSEIDON_GEOMETRY degree={} advice_columns={} advice_queries={} fixed_columns_before_selector_compression={} fixed_queries_before_selector_compression={} permutation_columns={} blinding_factors={} minimum_rows={} max_record_rows={} owned_working_fields=8",
        meta.degree(),
        meta.num_advice_columns(),
        meta.advice_queries().len(),
        meta.num_fixed_columns(),
        meta.fixed_queries().len(),
        meta.permutation().columns().len(),
        meta.blinding_factors(),
        meta.minimum_rows(),
        hash_rows(MAX_FIELDS)
    );
}

#[test]
fn maximum_record_matches_native_and_refuses_insufficient_rows() {
    fn check<F: PastaField>() {
        let circuit = HashCircuit::new(std::array::from_fn::<_, MAX_FIELDS, _>(|i| {
            F::from(17 * i as u64 + 3)
        }));
        assert!(matches!(
            circuit.check(15, vec![circuit.expected()]),
            Err(Error::NotEnoughRowsAvailable { current_k: 15 })
        ));
        circuit
            .check(16, vec![circuit.expected()])
            .unwrap()
            .into_result()
            .expect("all constraints hold");
    }
    check::<Fp>();
    check::<Fq>();
}

fn genuine_ipa<const L: usize>(circuit: HashCircuit<Fp, L>, k: u32) {
    HashCircuit::<Fp, L>::preflight(k).unwrap();
    let started = Instant::now();
    let setup = NativeProof::new(k, &circuit);
    let vk_bytes = setup.key_bytes();
    let keygen_ms = started.elapsed().as_secs_f64() * 1000.0;
    let public = circuit.expected();
    let started = Instant::now();
    let proof = setup.prove(circuit, &public);
    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    setup.verify(&public, &proof).unwrap();
    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
    let wrong = [public[0] + Fp::ONE];
    assert!(setup.verify(&wrong, &proof).is_err());
    let mut changed = proof.clone();
    changed[0] ^= 1;
    assert!(setup.verify(&public, &changed).is_err());
    let mut suffixed = proof.clone();
    suffixed.push(0);
    assert!(setup.verify(&public, &suffixed).is_err());
    assert!(proof.len() < 192 * 1024);
    println!(
        "RAM_LFE_POSEIDON_METRICS k={k} inputs={L} hash_rows={} proof_bytes={} vk_bytes={vk_bytes} keygen_ms={keygen_ms:.3} prove_ms={prove_ms:.3} verify_ms={verify_ms:.3} owned_input_bytes={} owned_working_fields=8",
        hash_rows(L),
        proof.len(),
        L * 32
    );
}

#[test]
fn genuine_ipa_sample_rejects_wrong_instance_tamper_and_trailing_bytes() {
    genuine_ipa(
        HashCircuit::new([Fp::from(3), Fp::from(7), Fp::from(11)]),
        8,
    );
}

#[test]
fn genuine_ipa_maximum_rejects_wrong_instance_tamper_and_trailing_bytes() {
    genuine_ipa(
        HashCircuit::new(std::array::from_fn::<_, MAX_FIELDS, _>(|i| {
            Fp::from(17 * i as u64 + 3)
        })),
        16,
    );
}
