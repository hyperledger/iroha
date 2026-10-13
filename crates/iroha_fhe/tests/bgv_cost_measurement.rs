//! The equal RAM-LFE-shaped workload over two plaintext encodings, measured phase by phase.
//!
//! One workload runs unchanged over the F257 sparse scalar subalgebra and over
//! a fully splitting batching modulus, so their costs can be compared:
//!
//! 1. **Client input.** Encode 64 input slots (a length, bytes, zeros), check
//!    the plaintext-side admission predicate (scalar subalgebra, length,
//!    byte ranges, zero padding) and encrypt.
//! 2. **Load.** `LoadInput` for two slots: multiply by the slot idempotent,
//!    broadcast with `log2(slots)` automorphisms and key switches, switch down.
//! 3. **Equality.** `SelectEqZero`: raise the condition to `t - 1` by
//!    square-and-multiply with a modulus switch after every multiplication,
//!    multiply by the embedded one as the V1 tape contract does, form the
//!    indicator `1 - c^(t-1)` and multiply it by the branch difference.
//! 4. **Output.** Place two outputs by slot masks, add them, and multiply by
//!    the mask that zeroes every unused output slot.
//! 5. **Open.** Decrypt and decode; the result is compared with the cleartext
//!    evaluation of the same instructions.
//!
//! A second group of phases runs each primitive five times at the top level.
//!
//! A second workload, the tape instruction profile, runs one instruction of
//! every V1 opcode through the costing harness of `tests/support/machine.rs`
//! on operands loaded at the top level, one phase per opcode, and records the
//! operations and model work units the harness charged to each. It gives the
//! measured time of every instruction beside its modelled cost.
//!
//! The default test run executes both encodings on small rings and checks the
//! results and the records. The `#[ignore]`d tests run the full-size profiles
//! and are meant for `scripts/zk_resource_harness.py`, which pins the binary,
//! observes the process and judges the records:
//!
//! ```text
//! cargo test -p iroha_fhe --release --test bgv_cost_measurement --no-run
//! python3 scripts/zk_resource_harness.py run --hardware <record> --profile release \
//!     --config bgv-f257-sparse-n16 --cache-policy warm -- \
//!     target/release/deps/bgv_cost_measurement-<hash> --ignored --exact \
//!     measure_f257_sparse_bounded_candidate --test-threads 1
//! ```
//!
//! Only public geometry is recorded: static labels, sizes, operation counts,
//! model work units and bit lengths of public noise bounds. No key, plaintext
//! or coin reaches the recorder. Nothing here establishes security; a
//! measured profile is a cost probe unless its parameters are separately
//! qualified.
mod support;

use std::path::{Path, PathBuf};

use support::machine::{
    Cleartext, Encrypted, Instruction, Machine, OPCODE_NAMES, Work as TapeWork, families,
};

use iroha_fhe::bgv::{
    BgvCandidate, BgvError, BgvParameters, BgvProfile, Ciphertext, EvaluationKeys, Plaintext,
    PublicKey, SecretKey, SlotEncoding, SwitchingKey, cost::CostModel,
};
use iroha_measurement::{
    ByteKind, CollectingSink, Declaration, DeclaredClass, DirectoryReport, DirectorySink, Finding,
    FlowKind, HARNESS_OUTPUT_DIR_ENV, MeasurementRecord, RecordSink, RunContext, RunIdentity,
    RunOutcome, Session, TeeSink, Unit, WorkerDeclaration, read_harness_context,
    unclassified_numbers,
};

const EMITTER: &str = "rust.iroha_fhe.bgv_cost";

/// RAM-LFE V1 input shape, restated here: this crate does not depend on the policy crate.
const INPUT_SLOTS: usize = 64;
/// Largest input byte length: one slot holds the length.
const MAX_INPUT_BYTES: usize = INPUT_SLOTS - 1;
/// Outputs the workload emits.
const OUTPUT_COUNT: usize = 2;
/// Calls of each primitive in the operation profile.
const OPERATION_REPETITIONS: usize = 5;

/// One measured configuration.
#[derive(Clone, Copy)]
struct Configuration {
    /// Workload label of the record.
    workload: &'static str,
    /// File stem of the record under a harness.
    stem: &'static str,
    /// The condition slot holds zero (the equality selects the zero branch) or a non-zero byte.
    condition_is_zero: bool,
}

/// Identity context and output directory handed over by the harness, if any.
/// This diagnostic-only variable selects where public records are written.
fn harness() -> (RunContext, Option<PathBuf>) {
    std::env::var_os(HARNESS_OUTPUT_DIR_ENV)
        .map(PathBuf::from)
        .map_or_else(
            || (RunContext::unbound(), None),
            |directory| {
                (
                    read_harness_context(&directory).expect("harness context"),
                    Some(directory),
                )
            },
        )
}

/// Where a measured flow delivers its record: memory, and a directory under a harness.
struct Delivery {
    memory: CollectingSink,
    files: Option<DirectoryReport>,
}

impl Delivery {
    fn new(directory: Option<&Path>, stem: &'static str) -> (Box<dyn RecordSink>, Self) {
        let memory = CollectingSink::new();
        let collector: Box<dyn RecordSink> = Box::new(memory.clone());
        match directory {
            Some(directory) => {
                let files = DirectorySink::new(directory.to_path_buf(), stem);
                let report = files.report();
                (
                    Box::new(TeeSink::new(collector, Box::new(files))),
                    Self {
                        memory,
                        files: Some(report),
                    },
                )
            }
            None => (
                collector,
                Self {
                    memory,
                    files: None,
                },
            ),
        }
    }

    fn only(&self) -> MeasurementRecord {
        let mut records = self.memory.take();
        assert_eq!(records.len(), 1);
        if let Some(files) = &self.files {
            assert!(files.errors().is_empty(), "{:?}", files.errors());
            assert!(files.partial().is_empty());
            assert_eq!(files.written().len(), 1);
        }
        records.remove(0)
    }
}

/// The RAM-LFE input vector: slot 0 the length, then bytes, then zeros.
fn input_slots(condition_is_zero: bool, modulus: u64) -> Vec<u64> {
    let length = 40_usize;
    let mut slots = vec![0_u64; INPUT_SLOTS];
    slots[0] = length as u64;
    for (index, slot) in slots.iter_mut().enumerate().skip(1).take(length) {
        *slot = (index as u64 * 37 + 11) % 256 % modulus;
    }
    // The workload reads slot 5 as the condition and slot 9 as the zero branch.
    slots[CONDITION_SLOT] = if condition_is_zero { 0 } else { 173 % modulus };
    slots
}

const CONDITION_SLOT: usize = 5;
const ZERO_BRANCH_SLOT: usize = 9;
/// The plaintext constant of the non-zero branch.
const NONZERO_BRANCH: u64 = 77;

/// The plaintext-side admission predicate of a RAM-LFE input: scalar subalgebra, a length of
/// at most 63, bytes in the declared positions and zeros everywhere else.
fn admit_input(encoding: &SlotEncoding, plaintext: &Plaintext) -> Result<(), BgvError> {
    let slots = encoding.decode(plaintext)?;
    let length = usize::try_from(slots[0]).unwrap_or(usize::MAX);
    if length > MAX_INPUT_BYTES {
        return Err(BgvError::NonCanonical { index: 0 });
    }
    for (index, &value) in slots.iter().enumerate().skip(1) {
        let allowed = if index <= length { 255 } else { 0 };
        if value > allowed {
            return Err(BgvError::NonCanonical { index });
        }
    }
    Ok(())
}

/// Counters of the operations a phase performed, reported as public work.
#[derive(Clone, Copy, Default)]
struct Work {
    multiplications: u64,
    key_switches: u64,
    plaintext_multiplications: u64,
    modulus_switches: u64,
    model_units: u64,
}

struct Evaluator<'a> {
    profile: &'a BgvProfile,
    model: CostModel<'a>,
    keys: &'a EvaluationKeys,
    work: Work,
}

impl Evaluator<'_> {
    fn relinearization(&self) -> &SwitchingKey {
        self.keys.relinearization()
    }

    fn switch_down(&mut self, ciphertext: &Ciphertext) -> Result<Ciphertext, BgvError> {
        self.work.modulus_switches += 1;
        self.work.model_units += self.model.switch_down_units(ciphertext.level())?;
        self.profile.switch_down(ciphertext)
    }

    fn switch_to_level(
        &mut self,
        ciphertext: &Ciphertext,
        level: usize,
    ) -> Result<Ciphertext, BgvError> {
        let mut current = ciphertext.clone();
        while current.level() > level {
            current = self.switch_down(&current)?;
        }
        Ok(current)
    }

    /// Multiply two ciphertexts at their common lower level, relinearize and drop one prime.
    fn multiply_then_switch(
        &mut self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
    ) -> Result<Ciphertext, BgvError> {
        let level = lhs.level().min(rhs.level());
        let lhs = self.switch_to_level(lhs, level)?;
        let rhs = self.switch_to_level(rhs, level)?;
        self.work.multiplications += 1;
        self.work.key_switches += 1;
        self.work.model_units += self.model.multiplication_units(level)?;
        let product = self.profile.multiply(&lhs, &rhs, self.relinearization())?;
        self.switch_down(&product)
    }

    fn mul_plain(
        &mut self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext, BgvError> {
        self.work.plaintext_multiplications += 1;
        self.work.model_units += self
            .model
            .plaintext_multiplication_units(ciphertext.level())?;
        self.profile.mul_plain(ciphertext, plaintext)
    }

    /// `base^exponent` by right-to-left square-and-multiply; the exponent is public.
    fn power(&mut self, base: &Ciphertext, mut exponent: u64) -> Result<Ciphertext, BgvError> {
        let mut base = base.clone();
        let mut result: Option<Ciphertext> = None;
        loop {
            if exponent & 1 == 1 {
                result = Some(match result {
                    None => base.clone(),
                    Some(partial) => self.multiply_then_switch(&partial, &base)?,
                });
            }
            exponent >>= 1;
            if exponent == 0 {
                break;
            }
            base = self.multiply_then_switch(&base, &base)?;
        }
        result.ok_or(BgvError::Kernel)
    }

    /// Report and reset the counters of the phase that just ended.
    fn report(&mut self, session: &Session) {
        let work = std::mem::take(&mut self.work);
        for (label, value) in [
            ("ciphertext_multiplications", work.multiplications),
            ("key_switches", work.key_switches),
            ("plaintext_multiplications", work.plaintext_multiplications),
            ("modulus_switches", work.modulus_switches),
            ("model_work_units", work.model_units),
        ] {
            if value != 0 {
                session.record_work(label, value);
            }
        }
    }
}

/// What a completed run produced, for the assertions of the caller.
struct Outcome {
    record: MeasurementRecord,
    results: Results,
}

/// The public results of the workload itself.
struct Results {
    outputs: Vec<u64>,
    expected: Vec<u64>,
    slots: usize,
    galois_keys: usize,
    multiplications: u64,
    final_level: usize,
}

fn words(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Run the equal workload on `parameters` inside one measured session.
fn run_workload(
    parameters: BgvParameters,
    configuration: Configuration,
) -> Result<Outcome, BgvError> {
    let (context, directory) = harness();
    let (sink, delivery) = Delivery::new(directory.as_deref(), configuration.stem);
    let session = Session::begin(
        RunIdentity::new(context, configuration.workload, FlowKind::Native, EMITTER),
        "equal_workload",
        WorkerDeclaration {
            workers: 1,
            provenance: "iroha_fhe.bgv.scalar_single_thread",
        },
        sink,
    );
    let result = measured(&session, parameters, configuration);
    if result.is_err() {
        // Only the stage and a fixed code are recorded, never the error payload.
        session.record_failure("equal_workload", "bgv_error");
    }
    session.finish();
    let record = delivery.only();
    if result.is_err() {
        assert_eq!(record.outcome, RunOutcome::Failed);
    }
    result.map(|results| Outcome { record, results })
}

fn measured(
    session: &Session,
    parameters: BgvParameters,
    configuration: Configuration,
) -> Result<Results, BgvError> {
    // Profile and encoding.
    let phase = session.enter("profile");
    let profile = BgvProfile::new(parameters)?;
    let encoding = SlotEncoding::new(&profile)?;
    let model = CostModel::new(&profile);
    let top = profile.top_level();
    let modulus = profile.plaintext_modulus();
    let broadcast = encoding.broadcast_elements();
    session.record_work("ring_degree", words(profile.degree()));
    session.record_work("main_primes", words(top + 1));
    session.record_work("special_primes", words(profile.special_count()));
    session.record_work("key_switch_digits", words(profile.digit_count()));
    session.record_work("scalar_slots", words(encoding.slots()));
    session.record_work("slot_mask_l1_norm", encoding.mask_bound().l1);
    session.record_work("modulus_bits", words(profile.level_modulus(top)?.bit_len()));
    session.record_work(
        "special_modulus_bits",
        words(profile.special_modulus().bit_len()),
    );
    session.record_work(
        "fresh_noise_bound_bits",
        words(profile.fresh_noise().bit_len()),
    );
    session.record_work(
        "key_switch_noise_bound_bits",
        words(profile.key_switch_noise(top)?.bit_len()),
    );
    phase.complete();

    // Keys.
    let phase = session.enter("key_generation");
    let step = session.enter("secret_key");
    let secret = SecretKey::generate(&profile)?;
    step.complete();
    let step = session.enter("public_key");
    let public = PublicKey::generate(&profile, &secret)?;
    session.record_bytes(ByteKind::Key, "public_key_frame", model.public_key_bytes());
    step.complete();
    let step = session.enter("evaluation_keys");
    let keys = EvaluationKeys::generate(&profile, &secret, &broadcast)?;
    session.record_bytes(
        ByteKind::Key,
        "switching_key_frame",
        model.switching_key_bytes(),
    );
    session.record_bytes(
        ByteKind::Key,
        "evaluation_keys_frame",
        model.evaluation_key_bytes(broadcast.len()),
    );
    session.record_work("galois_keys", words(broadcast.len()));
    step.complete();
    phase.complete();

    let mut evaluator = Evaluator {
        profile: &profile,
        model,
        keys: &keys,
        work: Work::default(),
    };

    // Client input.
    let phase = session.enter("client_input");
    let slots = input_slots(configuration.condition_is_zero, modulus);
    let step = session.enter("encode");
    let input = encoding.encode(&profile, &slots)?;
    step.complete();
    let step = session.enter("scalar_subalgebra_and_range_check");
    admit_input(&encoding, &input)?;
    session.record_work(
        "coefficients_checked_zero",
        words(profile.degree() - encoding.slots()),
    );
    session.record_work("slots_range_checked", words(encoding.slots()));
    step.complete();
    let step = session.enter("encrypt");
    let encrypted = public.encrypt(&profile, &input)?;
    session.record_work("model_work_units", model.encryption_units());
    session.record_bytes(
        ByteKind::Ciphertext,
        "input_ciphertext_frame",
        model.ciphertext_bytes(top, 2)?,
    );
    step.complete();
    phase.complete();

    // LoadInput for the condition and the zero branch.
    let phase = session.enter("load_input");
    let mut loaded = Vec::with_capacity(2);
    for slot in [CONDITION_SLOT, ZERO_BRANCH_SLOT] {
        let step = session.enter("mask_multiplication");
        let mask = encoding.slot_mask(&profile, slot)?;
        let mut current = evaluator.mul_plain(&encrypted, &mask)?;
        evaluator.report(session);
        step.complete();
        let step = session.enter("broadcast_key_switches");
        for &element in &broadcast {
            let key = keys.galois(element).ok_or(BgvError::WrongSwitchingKey)?;
            evaluator.work.key_switches += 1;
            evaluator.work.model_units += model.automorphism_units(current.level())?;
            let image = profile.apply_galois(&current, key)?;
            current = profile.add(&current, &image)?;
        }
        session.record_work("noise_bound_bits", words(current.noise_bound().bits()));
        evaluator.report(session);
        step.complete();
        let step = session.enter("modulus_switch");
        current = evaluator.switch_down(&current)?;
        session.record_work("noise_bound_bits", words(current.noise_bound().bits()));
        evaluator.report(session);
        step.complete();
        loaded.push(current);
    }
    let zero_branch = loaded.pop().ok_or(BgvError::Kernel)?;
    let condition = loaded.pop().ok_or(BgvError::Kernel)?;
    phase.complete();

    // SelectEqZero.
    let phase = session.enter("select_eq_zero");
    let step = session.enter("equality_exponentiation");
    let powered = evaluator.power(&condition, modulus - 1)?;
    let exponentiation_multiplications = evaluator.work.multiplications;
    session.record_work("noise_bound_bits", words(powered.noise_bound().bits()));
    evaluator.report(session);
    step.complete();
    let step = session.enter("embedded_one_multiplication");
    let one = Plaintext::constant(&profile, 1)?;
    let embedded_one = Ciphertext::trivial(&profile, &one, powered.level())?;
    let powered = evaluator.multiply_then_switch(&powered, &embedded_one)?;
    evaluator.report(session);
    step.complete();
    let step = session.enter("indicator");
    let indicator = profile.add_plain(&profile.negate(&powered)?, &one)?;
    step.complete();
    let step = session.enter("select_multiplication");
    let nonzero = Plaintext::constant(&profile, NONZERO_BRANCH % modulus)?;
    let difference = profile.sub_plain(&zero_branch, &nonzero)?;
    let selected = evaluator.multiply_then_switch(&indicator, &difference)?;
    let selected = profile.add_plain(&selected, &nonzero)?;
    session.record_work("noise_bound_bits", words(selected.noise_bound().bits()));
    evaluator.report(session);
    step.complete();
    phase.complete();

    // Outputs: the selected value in slot 0 and the condition in slot 1.
    let phase = session.enter("output");
    let step = session.enter("output_masking");
    let level = selected.level();
    let condition_low = evaluator.switch_to_level(&condition, level)?;
    let first = evaluator.mul_plain(&selected, &encoding.slot_mask(&profile, 0)?)?;
    let second = evaluator.mul_plain(&condition_low, &encoding.slot_mask(&profile, 1)?)?;
    let packed = profile.add(&first, &second)?;
    evaluator.report(session);
    step.complete();
    let step = session.enter("unused_output_zeroing");
    let packed = evaluator.mul_plain(&packed, &encoding.prefix_mask(&profile, OUTPUT_COUNT)?)?;
    session.record_work("noise_bound_bits", words(packed.noise_bound().bits()));
    session.record_work(
        "capacity_bits",
        words(profile.capacity(packed.level())?.bit_len()),
    );
    session.record_bytes(
        ByteKind::Ciphertext,
        "output_ciphertext_frame",
        model.ciphertext_bytes(packed.level(), 2)?,
    );
    evaluator.report(session);
    step.complete();
    phase.complete();

    // Open.
    let phase = session.enter("open");
    let step = session.enter("decrypt");
    let opened = secret.decrypt(&profile, &packed)?;
    session.record_work("model_work_units", model.decryption_units(packed.level())?);
    step.complete();
    let step = session.enter("decode");
    let outputs = encoding.decode(&opened)?.to_vec();
    step.complete();
    phase.complete();

    // Each primitive at the top level, repeated so one preempted call does not decide the time.
    let phase = session.enter("operation_profile");
    let fresh = public.encrypt(&profile, &input)?;
    let mut other = public.encrypt(&profile, &input)?;
    let mut tensor = profile.tensor(&fresh, &other)?;
    let mut product = profile.relinearize(&tensor, keys.relinearization())?;
    let galois = keys
        .galois(broadcast[0])
        .ok_or(BgvError::WrongSwitchingKey)?;
    for repetition in 0..OPERATION_REPETITIONS {
        // The model units of one call are reported once per primitive.
        let units = |value: u64| {
            if repetition == 0 {
                session.record_work("model_work_units", value);
            }
        };
        let step = session.enter("encryption");
        other = public.encrypt(&profile, &input)?;
        units(model.encryption_units());
        step.complete();
        let step = session.enter("decryption");
        let _ = secret.decrypt(&profile, &fresh)?;
        units(model.decryption_units(top)?);
        step.complete();
        let step = session.enter("addition");
        let _ = profile.add(&fresh, &other)?;
        step.complete();
        let step = session.enter("plaintext_multiplication");
        let _ = profile.mul_plain(&fresh, &one)?;
        units(model.plaintext_multiplication_units(top)?);
        step.complete();
        let step = session.enter("tensor");
        tensor = profile.tensor(&fresh, &other)?;
        units(model.tensor_units(top)?);
        step.complete();
        let step = session.enter("relinearization");
        product = profile.relinearize(&tensor, keys.relinearization())?;
        units(model.key_switch_units(top)?);
        step.complete();
        let step = session.enter("automorphism");
        let _ = profile.apply_galois(&fresh, galois)?;
        units(model.automorphism_units(top)?);
        step.complete();
        if top > 0 {
            let step = session.enter("modulus_switch");
            let _ = profile.switch_down(&product)?;
            units(model.switch_down_units(top)?);
            step.complete();
        }
    }
    phase.complete();

    // Declared model values: projections of the deterministic cost model, never measurements.
    for (label, value) in [
        (
            "model.multiplication_units_top_level",
            model.multiplication_units(top)?,
        ),
        (
            "model.key_switch_units_top_level",
            model.key_switch_units(top)?,
        ),
        (
            "model.plaintext_multiplication_units_top_level",
            model.plaintext_multiplication_units(top)?,
        ),
        (
            "model.key_switch_scratch_bytes_top_level",
            8 * model.key_switch_scratch_words(top)?,
        ),
    ] {
        session.declare(Declaration {
            class: DeclaredClass::Projection,
            label,
            unit: if label.ends_with("bytes_top_level") {
                Unit::Bytes
            } else {
                Unit::Count
            },
            value,
            provenance: "crates/iroha_fhe/src/bgv/cost.rs::CostModel",
        });
    }

    // Releasing the keys and ciphertexts clears them; that time belongs to a phase.
    let phase = session.enter("release");
    let final_level = packed.level();
    let galois_keys = broadcast.len();
    let slot_count = encoding.slots();
    drop((
        fresh,
        other,
        tensor,
        product,
        packed,
        opened,
        first,
        second,
        selected,
        indicator,
        difference,
        condition,
        zero_branch,
        condition_low,
        powered,
        embedded_one,
        encrypted,
        input,
    ));
    drop((keys, public, secret));
    drop(profile);
    phase.complete();

    // The cleartext evaluation of the same instructions.
    let condition_value = slots[CONDITION_SLOT];
    let selected_value = if condition_value == 0 {
        slots[ZERO_BRANCH_SLOT]
    } else {
        NONZERO_BRANCH % modulus
    };
    let mut expected = vec![0_u64; slot_count];
    expected[0] = selected_value;
    expected[1] = condition_value;
    Ok(Results {
        outputs,
        expected,
        slots: slot_count,
        galois_keys,
        multiplications: exponentiation_multiplications,
        final_level,
    })
}

/// Findings other than an identity the harness did not bind.
fn findings_beyond_unbound_identity(record: &MeasurementRecord, bound: bool) -> Vec<Finding> {
    record
        .findings()
        .into_iter()
        .filter(|finding| {
            bound
                || !matches!(
                    finding,
                    Finding::IdentityIncomplete { .. } | Finding::DirtyDigestMismatch
                )
        })
        .collect()
}

/// Phases every record of the equal workload has.
const EQUAL_WORKLOAD_PHASES: [&str; 14] = [
    "equal_workload",
    "key_generation",
    "scalar_subalgebra_and_range_check",
    "mask_multiplication",
    "broadcast_key_switches",
    "equality_exponentiation",
    "embedded_one_multiplication",
    "select_multiplication",
    "output_masking",
    "unused_output_zeroing",
    "decrypt",
    "operation_profile",
    "relinearization",
    "automorphism",
];

fn check_record(record: &MeasurementRecord, required_phases: &[&str]) {
    let bound = std::env::var_os(HARNESS_OUTPUT_DIR_ENV).is_some();
    assert_eq!(record.outcome, RunOutcome::Succeeded);
    assert_eq!(
        findings_beyond_unbound_identity(record, bound),
        Vec::<Finding>::new()
    );
    // Every number of the record's view carries a classification.
    assert!(unclassified_numbers(&record.to_json_value()).is_empty());
    let labels: Vec<&str> = record
        .phase_tree
        .nodes
        .iter()
        .map(|node| node.label.as_str())
        .collect();
    for required in required_phases {
        assert!(labels.contains(required), "missing phase {required}");
    }
    // Every phase completed and none unwound.
    for node in &record.phase_tree.nodes {
        assert_eq!(node.calls, node.completed, "{}", node.label);
        assert_eq!(node.unwound, 0, "{}", node.label);
    }
}

/// A small F257 ring: 128 scalar slots at stride two.
fn small_sparse_parameters() -> BgvParameters {
    BgvParameters::derive(8, 257, (40, 13), (41, 3), 2).expect("parameters")
}

/// A small fully splitting ring: 7681 = 1 mod 512.
fn small_batching_parameters() -> BgvParameters {
    BgvParameters::derive(8, 7681, (40, 18), (41, 3), 2).expect("parameters")
}

#[test]
fn equal_workload_selects_both_branches_over_the_sparse_f257_encoding() {
    for condition_is_zero in [true, false] {
        let outcome = run_workload(
            small_sparse_parameters(),
            Configuration {
                workload: "bgv.equal_workload.f257_sparse.small",
                stem: "bgv-equal-workload-f257-sparse-small",
                condition_is_zero,
            },
        )
        .expect("workload");
        assert_eq!(outcome.results.slots, 128);
        assert_eq!(outcome.results.galois_keys, 7);
        // x^256: eight squarings.
        assert_eq!(outcome.results.multiplications, 8);
        assert_eq!(outcome.results.outputs, outcome.results.expected);
        assert_eq!(outcome.results.outputs[1] == 0, condition_is_zero);
        assert!(outcome.results.final_level >= 1);
        check_record(&outcome.record, &EQUAL_WORKLOAD_PHASES);
    }
}

#[test]
fn equal_workload_selects_both_branches_over_a_fully_splitting_modulus() {
    for condition_is_zero in [true, false] {
        let outcome = run_workload(
            small_batching_parameters(),
            Configuration {
                workload: "bgv.equal_workload.batching.small",
                stem: "bgv-equal-workload-batching-small",
                condition_is_zero,
            },
        )
        .expect("workload");
        assert_eq!(outcome.results.slots, 256);
        assert_eq!(outcome.results.galois_keys, 8);
        // x^7680 = x^(15 * 2^9): twelve squarings and three products.
        assert_eq!(outcome.results.multiplications, 15);
        assert_eq!(outcome.results.outputs, outcome.results.expected);
        check_record(&outcome.record, &EQUAL_WORKLOAD_PHASES);
    }
}

#[test]
fn a_chain_too_short_for_the_workload_is_refused_and_recorded_as_a_failure() {
    // Six 40-bit primes cannot hold eight squarings: the noise budget runs out, the workload
    // returns the refusal and the record keeps the failure.
    let parameters = BgvParameters::derive(8, 257, (40, 6), (41, 3), 2).expect("parameters");
    let result = run_workload(
        parameters,
        Configuration {
            workload: "bgv.equal_workload.f257_sparse.too_short",
            stem: "bgv-equal-workload-too-short",
            condition_is_zero: true,
        },
    );
    assert!(matches!(
        result.err(),
        Some(BgvError::NoiseBudgetExceeded { .. } | BgvError::NoLevelLeft)
    ));
}

#[test]
fn the_admission_predicate_rejects_malformed_inputs() {
    let profile = BgvProfile::new(small_sparse_parameters()).expect("profile");
    let encoding = SlotEncoding::new(&profile).expect("encoding");
    let admit = |slots: &[u64]| {
        admit_input(
            &encoding,
            &encoding.encode(&profile, slots).expect("encoded"),
        )
    };
    assert_eq!(admit(&input_slots(true, 257)), Ok(()));
    // A length of 64, a byte of 256, a non-zero slot past the length and one past slot 63.
    let mut slots = input_slots(true, 257);
    slots[0] = 64;
    assert_eq!(admit(&slots), Err(BgvError::NonCanonical { index: 0 }));
    let mut slots = input_slots(true, 257);
    slots[3] = 256;
    assert_eq!(admit(&slots), Err(BgvError::NonCanonical { index: 3 }));
    let mut slots = input_slots(true, 257);
    slots[41] = 1;
    assert_eq!(admit(&slots), Err(BgvError::NonCanonical { index: 41 }));
    let mut slots = input_slots(true, 257);
    slots.resize(128, 0);
    slots[100] = 1;
    assert_eq!(admit(&slots), Err(BgvError::NonCanonical { index: 100 }));
    // A plaintext outside the scalar subalgebra is rejected before any range check.
    let mut coefficients = vec![0_u64; 256];
    coefficients[1] = 1;
    let outside = Plaintext::new(&profile, coefficients).expect("plaintext");
    assert_eq!(
        admit_input(&encoding, &outside),
        Err(BgvError::OutsideScalarSubalgebra { index: 1 })
    );
}

fn run_full_size(
    parameters: BgvParameters,
    workload: &'static str,
    stem: &'static str,
    condition_is_zero: bool,
) {
    let outcome = run_workload(
        parameters,
        Configuration {
            workload,
            stem,
            condition_is_zero,
        },
    )
    .expect("workload");
    assert_eq!(outcome.results.outputs, outcome.results.expected);
    assert_eq!(outcome.results.outputs[1] == 0, condition_is_zero);
    check_record(&outcome.record, &EQUAL_WORKLOAD_PHASES);
}

/// What a completed tape instruction profile produced.
struct TapeOutcome {
    record: MeasurementRecord,
    outputs: Vec<u64>,
    expected: Vec<u64>,
    instructions: usize,
}

/// Report the work one phase of the tape profile was charged.
fn report_work(session: &Session, before: TapeWork, after: TapeWork) {
    for (label, value) in [
        (
            "plaintext_multiplications",
            after.plaintext_multiplications - before.plaintext_multiplications,
        ),
        ("key_switches", after.key_switches - before.key_switches),
        (
            "ciphertext_multiplications",
            after.multiplications - before.multiplications,
        ),
        (
            "modulus_switches",
            after.modulus_switches - before.modulus_switches,
        ),
        ("model_work_units", after.units - before.units),
    ] {
        if value != 0 {
            session.record_work(label, value);
        }
    }
}

/// Run `tape` through the costing harness inside one measured session, one phase per opcode.
fn run_tape_profile(
    parameters: BgvParameters,
    workload: &'static str,
    stem: &'static str,
    tape: &[Instruction],
) -> Result<TapeOutcome, BgvError> {
    let (context, directory) = harness();
    let (sink, delivery) = Delivery::new(directory.as_deref(), stem);
    let session = Session::begin(
        RunIdentity::new(context, workload, FlowKind::Native, EMITTER),
        "tape_instruction_profile",
        WorkerDeclaration {
            workers: 1,
            provenance: "iroha_fhe.bgv.scalar_single_thread",
        },
        sink,
    );
    let result = measured_tape(&session, parameters, tape);
    if result.is_err() {
        session.record_failure("tape_instruction_profile", "bgv_error");
    }
    session.finish();
    let record = delivery.only();
    result.map(|(outputs, expected)| TapeOutcome {
        record,
        outputs,
        expected,
        instructions: tape.len(),
    })
}

fn measured_tape(
    session: &Session,
    parameters: BgvParameters,
    tape: &[Instruction],
) -> Result<(Vec<u64>, Vec<u64>), BgvError> {
    let phase = session.enter("profile");
    let profile = BgvProfile::new(parameters)?;
    let encoding = SlotEncoding::new(&profile)?;
    let model = CostModel::new(&profile);
    let top = profile.top_level();
    let broadcast = encoding.broadcast_elements();
    session.record_work("ring_degree", words(profile.degree()));
    session.record_work("main_primes", words(top + 1));
    session.record_work("special_primes", words(profile.special_count()));
    session.record_work("scalar_slots", words(encoding.slots()));
    phase.complete();

    let phase = session.enter("key_generation");
    let secret = SecretKey::generate(&profile)?;
    let public = PublicKey::generate(&profile, &secret)?;
    let keys = EvaluationKeys::generate(&profile, &secret, &broadcast)?;
    session.record_bytes(
        ByteKind::Key,
        "evaluation_keys_frame",
        model.evaluation_key_bytes(broadcast.len()),
    );
    phase.complete();

    let phase = session.enter("client_input");
    let slots = input_slots(false, profile.plaintext_modulus());
    let input = encoding.encode(&profile, &slots)?;
    let encrypted = public.encrypt(&profile, &input)?;
    session.record_bytes(
        ByteKind::Ciphertext,
        "input_ciphertext_frame",
        model.ciphertext_bytes(top, 2)?,
    );
    phase.complete();

    // The machine: the input, four registers and 32 lanes at the top level.
    let phase = session.enter("machine_setup");
    let initial_state: Vec<u64> = (0..32).map(|lane| (lane * 29 + 3) % 257).collect();
    let backend = Encrypted::new(&profile, &keys, encrypted)?;
    let mut machine = Machine::new(backend, &profile, &initial_state)?;
    let mut cleartext = Cleartext::new(&slots, &initial_state);
    phase.complete();

    let phase = session.enter("tape");
    for instruction in tape {
        let step = session.enter(OPCODE_NAMES[instruction.tag()]);
        let before = machine.ledger().total;
        machine.step(*instruction)?;
        cleartext.step(*instruction);
        report_work(session, before, machine.ledger().total);
        step.complete();
    }
    let step = session.enter("final_zeroing_mask");
    let before = machine.ledger().total;
    let (packed, ledger) = machine.finish()?;
    report_work(session, before, ledger.total);
    session.record_work("noise_bound_bits", words(packed.noise_bound().bits()));
    session.record_work(
        "capacity_bits",
        words(profile.capacity(packed.level())?.bit_len()),
    );
    session.record_work("output_level", words(packed.level()));
    session.record_bytes(
        ByteKind::Ciphertext,
        "output_ciphertext_frame",
        model.ciphertext_bytes(packed.level(), 2)?,
    );
    step.complete();
    phase.complete();

    // Declared model values: the harness's own projection of the live buffers.
    for (label, value) in [
        (
            "model.peak_persistent_ciphertext_bytes",
            ledger.peak_persistent_bytes,
        ),
        ("model.peak_working_bytes", ledger.peak_working_bytes),
    ] {
        session.declare(Declaration {
            class: DeclaredClass::Projection,
            label,
            unit: Unit::Bytes,
            value,
            provenance: "crates/iroha_fhe/tests/support/machine.rs::Ledger",
        });
    }
    session.declare(Declaration {
        class: DeclaredClass::Projection,
        label: "model.tape_work_units",
        unit: Unit::Count,
        value: ledger.total.units,
        provenance: "crates/iroha_fhe/tests/support/machine.rs::Ledger",
    });

    let phase = session.enter("open");
    let opened = secret.decrypt(&profile, &packed)?;
    let outputs = encoding.decode(&opened)?.to_vec();
    phase.complete();

    // Releasing the registers, the lanes, the keys and the ciphertexts clears them.
    let phase = session.enter("release");
    drop(machine);
    drop((packed, opened, input));
    drop((keys, public, secret));
    phase.complete();

    let mut expected = cleartext.outputs.clone();
    expected.resize(outputs.len(), 0);
    Ok((outputs, expected))
}

fn check_tape_outcome(outcome: &TapeOutcome, tape: &[Instruction]) {
    assert_eq!(outcome.outputs, outcome.expected);
    assert_eq!(outcome.instructions, tape.len());
    let mut required = vec![
        "tape_instruction_profile",
        "key_generation",
        "client_input",
        "machine_setup",
        "tape",
        "final_zeroing_mask",
        "open",
    ];
    required.extend(
        tape.iter()
            .map(|instruction| OPCODE_NAMES[instruction.tag()]),
    );
    check_record(&outcome.record, &required);
    // One phase per opcode, entered once per instruction of that opcode.
    for (tag, name) in OPCODE_NAMES.iter().enumerate() {
        let instructions = tape
            .iter()
            .filter(|instruction| instruction.tag() == tag)
            .count();
        let calls: u64 = outcome
            .record
            .phase_tree
            .nodes
            .iter()
            .filter(|node| node.label == *name)
            .map(|node| node.calls)
            .sum();
        assert_eq!(calls, instructions as u64, "{name}");
    }
}

#[test]
fn tape_instruction_profile_runs_every_opcode_and_records_one_phase_each() {
    // Every opcode of bounded.v1 on a small ring; the affine profile is its prefix.
    for (tape, primes) in [
        (families::instruction_profile_bounded(), 13),
        (families::instruction_profile_affine(), 4),
    ] {
        let parameters =
            BgvParameters::derive(8, 257, (40, primes), (41, 3), 2).expect("parameters");
        let outcome = run_tape_profile(
            parameters,
            "bgv.tape_instruction_profile.small",
            "bgv-tape-profile-small",
            &tape,
        )
        .expect("profile");
        check_tape_outcome(&outcome, &tape);
        // Two outputs in the first two slots and zero in every other slot.
        assert_eq!(outcome.outputs.len(), 128);
        assert!(outcome.outputs[2..].iter().all(|&slot| slot == 0));
    }
    // A chain too short for the select is refused and the record keeps the failure.
    let parameters = BgvParameters::derive(8, 257, (40, 5), (41, 3), 2).expect("parameters");
    let result = run_tape_profile(
        parameters,
        "bgv.tape_instruction_profile.too_short",
        "bgv-tape-profile-too-short",
        &families::instruction_profile_bounded(),
    );
    assert!(matches!(
        result.err(),
        Some(BgvError::NoiseBudgetExceeded { .. } | BgvError::NoLevelLeft)
    ));
}

fn run_full_size_tape(
    candidate: BgvCandidate,
    workload: &'static str,
    stem: &'static str,
    tape: &[Instruction],
) {
    let outcome = run_tape_profile(candidate.parameters(), workload, stem, tape).expect("profile");
    check_tape_outcome(&outcome, tape);
}

/// The bounded candidate: `N = 2^16`, `t = 257`, 22 + 2 primes, 128 sparse slots.
#[test]
#[ignore = "full-size measurement: run under scripts/zk_resource_harness.py in a release build"]
fn measure_f257_sparse_bounded_candidate() {
    run_full_size(
        BgvCandidate::BoundedF257.parameters(),
        "bgv.equal_workload.f257_sparse.n16",
        "bgv-equal-workload-f257-sparse-n16",
        true,
    );
}

/// The same workload on the non-zero branch of the select.
#[test]
#[ignore = "full-size measurement: run under scripts/zk_resource_harness.py in a release build"]
fn measure_f257_sparse_bounded_candidate_nonzero_branch() {
    run_full_size(
        BgvCandidate::BoundedF257.parameters(),
        "bgv.equal_workload.f257_sparse.n16.nonzero",
        "bgv-equal-workload-f257-sparse-n16-nonzero",
        false,
    );
}

/// One instruction of every opcode on the bounded candidate, one phase each.
#[test]
#[ignore = "full-size measurement: run under scripts/zk_resource_harness.py in a release build"]
fn measure_tape_instruction_profile_bounded_candidate() {
    run_full_size_tape(
        BgvCandidate::BoundedF257,
        "bgv.tape_instruction_profile.bounded.n16",
        "bgv-tape-profile-bounded-n16",
        &families::instruction_profile_bounded(),
    );
}

/// One instruction of every affine opcode on the affine candidate itself.
#[test]
#[ignore = "full-size measurement: run under scripts/zk_resource_harness.py in a release build"]
fn measure_tape_instruction_profile_affine_candidate() {
    run_full_size_tape(
        BgvCandidate::AffineF257,
        "bgv.tape_instruction_profile.affine.n14",
        "bgv-tape-profile-affine-n14",
        &families::instruction_profile_affine(),
    );
}

/// A fully splitting modulus at the same degree: `t = 786433`, 25 60-bit main primes and
/// three special primes, the shortest chain on which the workload is admitted.
///
/// The primes are 60-bit because the workload switches one prime per multiplication: at
/// this plaintext modulus the rounding floor of a switch is about 36 bits, a product of two
/// values at the floor about 87 bits, and one 50-bit prime cannot bring it back.
#[test]
#[ignore = "full-size measurement: run under scripts/zk_resource_harness.py in a release build"]
fn measure_batching_fully_split_n16() {
    run_full_size(
        BgvParameters::derive(16, 786_433, (60, 25), (60, 3), 2).expect("parameters"),
        "bgv.equal_workload.batching_t786433.n16",
        "bgv-equal-workload-batching-t786433-n16",
        true,
    );
}

/// The affine candidate cannot hold an equality; its operation profile is measured on the
/// load and output part of the workload at `N = 2^14` with a chain long enough for it.
#[test]
#[ignore = "full-size measurement: run under scripts/zk_resource_harness.py in a release build"]
fn measure_f257_sparse_n14_cost_probe() {
    run_full_size(
        BgvParameters::derive(14, 257, (50, 13), (60, 2), 2).expect("parameters"),
        "bgv.equal_workload.f257_sparse.n14_probe",
        "bgv-equal-workload-f257-sparse-n14-probe",
        true,
    );
}
