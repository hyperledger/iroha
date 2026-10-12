//! The tracked cost summary against the Rust cost model, noise rules and costing harness.
//!
//! `specs/fhe_bgv_cost_summary.json` is written by
//! `scripts/fhe_bgv_cost_model.py`, which recomputes it with its own model.
//! That alone would leave the summary unchecked against the code it
//! describes. The script therefore also renders the numbers below from the
//! summary into `tests/vectors/bgv_cost_model_v1.txt`, and refuses a summary
//! whose rendering differs from that file. This test recomputes each of them
//! from the crate:
//!
//! - geometry, sizes and work units from [`BgvProfile`], [`SlotEncoding`] and
//!   [`CostModel`], for the pinned candidates and the measured profiles;
//! - the cost of one instruction of every opcode, the plan of every
//!   maximum-shape tape family and the longest chains that fit, from the
//!   shape run of the costing harness (`tests/support/machine.rs`);
//! - the fewest main primes a family needs, by planning it on that chain and
//!   on the chain one prime shorter;
//! - the values proposed for the open inputs of the resource contract.
//!
//! Every key of every section has to be read by a check, so a number cannot
//! enter the view without a Rust recomputation. A change of a transfer rule, a
//! work-unit formula, a frame layout, a candidate or the lowering fails here
//! until the summary is regenerated. The view does not hold the script's
//! proof-work projections, its affine-map proposal or its core-SVP sanity
//! numbers; those are formulas of the script alone.
mod support;

use std::{cell::RefCell, collections::BTreeMap, collections::BTreeSet};

use iroha_fhe::{
    bgv::{
        BgvCandidate, BgvError, BgvParameters, BgvProfile, CiphertextShape, Plaintext,
        SlotEncoding, cost::CostModel,
    },
    rns_chain::MAX_BASIS_PRIMES,
};
use support::{
    kat::{Kat, Section},
    machine::{
        BOUNDED_MAX_RANK, INPUT_SLOTS, Instruction, Ledger, MAX_INSTRUCTIONS, MAX_OUTPUTS,
        OPCODE_NAMES, REGISTERS, SELECT_MULTIPLICATIONS, STATE_LANES, TapePlan, Work, families,
        flooded_bound, plan_tape,
    },
};

/// The view of the summary, embedded at compile time.
const VIEW: &str = include_str!("vectors/bgv_cost_model_v1.txt");

/// A section whose every key has to be read.
struct Checked<'kat> {
    name: &'kat str,
    section: Section<'kat>,
    read: RefCell<BTreeSet<String>>,
}

impl<'kat> Checked<'kat> {
    fn new(kat: &'kat Kat, name: &'kat str) -> Self {
        Self {
            name,
            section: kat.section(name),
            read: RefCell::new(BTreeSet::new()),
        }
    }

    fn text(&self, key: &str) -> &str {
        self.read.borrow_mut().insert(key.to_owned());
        self.section.text(key)
    }

    fn number(&self, key: &str) -> u64 {
        self.text(key)
            .parse()
            .unwrap_or_else(|_| panic!("{}: {key} is not a number", self.name))
    }

    /// A number, or `None` for the word `none`.
    fn optional(&self, key: &str) -> Option<u64> {
        match self.text(key) {
            "none" => None,
            text => Some(
                text.parse()
                    .unwrap_or_else(|_| panic!("{}: {key} is not a number", self.name)),
            ),
        }
    }

    fn flag(&self, key: &str) -> bool {
        match self.number(key) {
            0 => false,
            1 => true,
            other => panic!("{}: {key} = {other} is not a flag", self.name),
        }
    }

    fn has(&self, key: &str) -> bool {
        self.section.keys().contains(&key)
    }

    /// Assert `value` for `key`.
    fn expect(&self, key: &str, value: u64) {
        assert_eq!(self.number(key), value, "[{}] {key}", self.name);
    }

    fn expect_size(&self, key: &str, value: usize) {
        self.expect(key, value as u64);
    }

    /// Every key of the section was read by a check.
    fn finish(self) {
        let read = self.read.into_inner();
        let unread: Vec<&str> = self
            .section
            .keys()
            .into_iter()
            .filter(|key| !read.contains(*key))
            .collect();
        assert!(
            unread.is_empty(),
            "[{}] holds values no check recomputes: {unread:?}",
            self.name
        );
    }
}

/// The shape of a profile as the view writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Shape {
    log_degree: u32,
    plaintext_modulus: u64,
    main: (u32, usize),
    special: (u32, usize),
    digit_primes: usize,
}

impl Shape {
    fn parameters(self) -> BgvParameters {
        BgvParameters::derive(
            self.log_degree,
            self.plaintext_modulus,
            self.main,
            self.special,
            self.digit_primes,
        )
        .expect("parameters")
    }

    /// The same shape with `count` main primes. A chain shorter than a digit
    /// has digits of its own length, which is what the digit size means there.
    fn with_main_primes(self, count: usize) -> Self {
        Self {
            main: (self.main.0, count),
            digit_primes: self.digit_primes.min(count),
            ..self
        }
    }
}

/// Profiles by shape; a full-size profile takes a second to build in a debug test.
#[derive(Default)]
struct Profiles {
    built: BTreeMap<Shape, BgvProfile>,
}

impl Profiles {
    fn get(&mut self, shape: Shape) -> &BgvProfile {
        self.built
            .entry(shape)
            .or_insert_with(|| BgvProfile::new(shape.parameters()).expect("profile"))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing to a string");
        text
    })
}

/// Read and check the shape lines of a profile section.
fn read_shape(section: &Checked<'_>) -> Shape {
    let shape = Shape {
        log_degree: u32::try_from(section.number("log_degree")).expect("log degree"),
        plaintext_modulus: section.number("plaintext_modulus"),
        main: (
            u32::try_from(section.number("main_prime_bits")).expect("bits"),
            usize::try_from(section.number("main_primes")).expect("count"),
        ),
        special: (
            u32::try_from(section.number("special_prime_bits")).expect("bits"),
            usize::try_from(section.number("special_primes")).expect("count"),
        ),
        digit_primes: usize::try_from(section.number("digit_primes")).expect("digit"),
    };
    section.expect("error_eta", u64::from(iroha_fhe::bgv::ERROR_ETA));
    shape
}

/// Geometry, sizes and work units of one profile section against the crate.
fn check_profile_lines(section: &Checked<'_>, profile: &BgvProfile) {
    let parameters = profile.parameters();
    let encoding = SlotEncoding::new(profile).expect("encoding");
    let model = CostModel::new(profile);
    let top = profile.top_level();
    let broadcast = encoding.broadcast_elements().len();
    section.expect("first_main_prime", parameters.main_primes[0]);
    section.expect("last_main_prime", parameters.main_primes[top]);
    let special: Vec<String> = parameters
        .special_primes
        .iter()
        .map(u64::to_string)
        .collect();
    assert_eq!(section.text("special_prime_values"), special.join(","));
    section.expect_size(
        "modulus_bits",
        profile.level_modulus(top).expect("modulus").bit_len(),
    );
    section.expect_size("special_modulus_bits", profile.special_modulus().bit_len());
    section.expect_size("key_switch_digits", profile.digit_count());
    section.expect_size("scalar_slots", encoding.slots());
    section.expect("slot_mask_l1_norm", encoding.mask_bound().l1);
    section.expect_size("broadcast_key_switches", broadcast);
    section.expect_size("fresh_noise_bound_bits", profile.fresh_noise().bit_len());
    section.expect_size(
        "key_switch_noise_bound_bits",
        profile.key_switch_noise(top).expect("bound").bit_len(),
    );
    let ok = |value: Result<u64, BgvError>| value.expect("model value");
    section.expect(
        "size.ciphertext_frame_bytes_top_level",
        ok(model.ciphertext_bytes(top, 2)),
    );
    section.expect(
        "size.ciphertext_frame_bytes_lowest_level",
        ok(model.ciphertext_bytes(0, 2)),
    );
    section.expect("size.public_key_frame_bytes", model.public_key_bytes());
    section.expect(
        "size.secret_key_custody_frame_bytes",
        model.secret_key_bytes(),
    );
    section.expect(
        "size.switching_key_frame_bytes",
        model.switching_key_bytes(),
    );
    section.expect_size("size.galois_keys_for_broadcast", broadcast);
    section.expect(
        "size.evaluation_keys_frame_bytes",
        model.evaluation_key_bytes(broadcast),
    );
    section.expect(
        "size.key_switch_scratch_bytes_top_level",
        8 * ok(model.key_switch_scratch_words(top)),
    );
    section.expect(
        "work.multiplication_with_relinearization",
        ok(model.multiplication_units(top)),
    );
    section.expect("work.tensor", ok(model.tensor_units(top)));
    section.expect("work.key_switch", ok(model.key_switch_units(top)));
    section.expect(
        "work.plaintext_multiplication",
        ok(model.plaintext_multiplication_units(top)),
    );
    section.expect("work.modulus_switch", ok(model.switch_down_units(top)));
    section.expect("work.encryption", model.encryption_units());
    section.expect("work.decryption", ok(model.decryption_units(top)));
}

fn shape_of(candidate: BgvCandidate) -> Shape {
    let parameters = candidate.parameters();
    Shape {
        log_degree: parameters.log_degree,
        plaintext_modulus: parameters.plaintext_modulus,
        main: (50, parameters.main_primes.len()),
        special: (60, parameters.special_primes.len()),
        digit_primes: parameters.digit_primes,
    }
}

/// The class a candidate is intended for, from its position in the pinned list.
fn intended_class(candidate: BgvCandidate) -> &'static str {
    match candidate {
        BgvCandidate::AffineF257 => "affine.v1",
        BgvCandidate::BoundedF257 => "bounded.v1",
        BgvCandidate::RefreshF257 => "refresh.v1",
    }
}

/// The families planned on a candidate: every family its class admits.
fn candidate_families(candidate: BgvCandidate) -> Vec<(&'static str, Vec<Instruction>)> {
    families::all()
        .into_iter()
        .filter(|(class, _, _)| *class == "affine.v1" || candidate != BgvCandidate::AffineF257)
        .map(|(_, name, tape)| (name, tape))
        .collect()
}

fn instruction_profile(candidate: BgvCandidate) -> Vec<Instruction> {
    if candidate == BgvCandidate::AffineF257 {
        families::instruction_profile_affine()
    } else {
        families::instruction_profile_bounded()
    }
}

fn fitting(plan: TapePlan) -> (CiphertextShape, usize, Ledger) {
    match plan {
        TapePlan::Fits {
            output,
            capacity_bits,
            ledger,
        } => (output, capacity_bits, *ledger),
        TapePlan::Refused { instruction, tag } => {
            panic!("refused at instruction {instruction} (tag {tag})")
        }
    }
}

fn expect_work(section: &Checked<'_>, work: Work) {
    section.expect("plaintext_multiplications", work.plaintext_multiplications);
    section.expect("key_switches", work.key_switches);
    section.expect("multiplications", work.multiplications);
    section.expect("modulus_switches", work.modulus_switches);
    section.expect("work_units", work.units);
}

/// Whether `tape` fits `profile`, with the projected flood on its output when asked.
fn fits(profile: &BgvProfile, tape: &[Instruction], flooding: Option<(u32, u32)>) -> bool {
    match plan_tape(profile, tape).expect("plan") {
        TapePlan::Refused { .. } => false,
        TapePlan::Fits { output, .. } => flooding.is_none_or(|(releases, kappa)| {
            flooded_bound(profile, output.bound(), releases, kappa)
                <= *profile.capacity(output.level()).expect("capacity")
        }),
    }
}

/// Check a recorded fewest number of main primes: the tape fits that chain and not a shorter one.
fn check_minimal(
    profiles: &mut Profiles,
    shape: Shape,
    tape: &[Instruction],
    flooding: Option<(u32, u32)>,
    recorded: Option<u64>,
    label: &str,
) {
    let largest = MAX_BASIS_PRIMES - shape.special.1;
    match recorded {
        None => assert!(
            !fits(
                profiles.get(shape.with_main_primes(largest)),
                tape,
                flooding
            ),
            "{label}: fits {largest} main primes"
        ),
        Some(count) => {
            let count = usize::try_from(count).expect("count");
            assert!(
                fits(profiles.get(shape.with_main_primes(count)), tape, flooding),
                "{label}: does not fit {count} main primes"
            );
            assert!(
                count == 1
                    || !fits(
                        profiles.get(shape.with_main_primes(count - 1)),
                        tape,
                        flooding
                    ),
                "{label}: already fits {} main primes",
                count - 1
            );
        }
    }
}

/// The equal workload of `tests/bgv_cost_measurement.rs` over public shapes.
///
/// Its schedule differs from the costing harness: it switches one prime after
/// every multiplication and once after each load.
fn equal_workload_fits(profile: &BgvProfile) -> bool {
    fn run(profile: &BgvProfile) -> Result<(), BgvError> {
        let encoding = SlotEncoding::new(profile)?;
        let mask = encoding.mask_bound();
        let constant = Plaintext::constant_bound(profile);
        let multiply = |lhs: &CiphertextShape, rhs: &CiphertextShape| {
            let level = lhs.level().min(rhs.level());
            let lhs = profile.plan_switch_to_level(lhs, level)?;
            let rhs = profile.plan_switch_to_level(rhs, level)?;
            profile.plan_switch_down(&profile.plan_multiply(&lhs, &rhs)?)
        };
        let load = |encrypted: &CiphertextShape| {
            let mut current = profile.plan_mul_plain(encrypted, mask)?;
            for _ in encoding.broadcast_elements() {
                current = profile.plan_add(&current, &profile.plan_galois(&current)?)?;
            }
            profile.plan_switch_down(&current)
        };
        let encrypted = profile.plan_fresh()?;
        let condition = load(&encrypted)?;
        let zero_branch = load(&encrypted)?;
        // Right-to-left square-and-multiply to the exponent t - 1.
        let mut exponent = profile.plaintext_modulus() - 1;
        let mut base = condition.clone();
        let mut powered: Option<CiphertextShape> = None;
        loop {
            if exponent & 1 == 1 {
                powered = Some(match powered {
                    None => base.clone(),
                    Some(partial) => multiply(&partial, &base)?,
                });
            }
            exponent >>= 1;
            if exponent == 0 {
                break;
            }
            base = multiply(&base, &base)?;
        }
        let powered = powered.ok_or(BgvError::Kernel)?;
        let powered = multiply(&powered, &profile.plan_trivial(powered.level())?)?;
        let indicator = profile.plan_add_plain(&powered, constant)?;
        let difference = profile.plan_add_plain(&zero_branch, constant)?;
        let selected = profile.plan_add_plain(&multiply(&indicator, &difference)?, constant)?;
        let condition_low = profile.plan_switch_to_level(&condition, selected.level())?;
        let packed = profile.plan_add(
            &profile.plan_mul_plain(&selected, mask)?,
            &profile.plan_mul_plain(&condition_low, mask)?,
        )?;
        profile.plan_mul_plain(&packed, encoding.vector_bound())?;
        Ok(())
    }
    match run(profile) {
        Ok(()) => true,
        Err(BgvError::NoiseBudgetExceeded { .. } | BgvError::NoLevelLeft) => false,
        Err(other) => panic!("the equal workload cannot be planned: {other}"),
    }
}

#[test]
fn the_view_names_exactly_the_sections_this_test_recomputes() {
    let kat = Kat::parse(VIEW);
    let mut expected = vec!["shape".to_owned(), "refresh room".to_owned()];
    for candidate in BgvCandidate::ALL {
        let name = candidate.name();
        expected.push(format!("candidate {name}"));
        expected.push(format!("frontier {name}"));
        for (family, _) in candidate_families(candidate) {
            expected.push(format!("tape {name} {family}"));
        }
        let profile_tape = instruction_profile(candidate);
        for (tag, opcode) in OPCODE_NAMES.iter().enumerate() {
            if profile_tape.iter().any(|step| step.tag() == tag) {
                expected.push(format!("instruction {name} {opcode}"));
            }
        }
        expected.push(format!("instruction {name} final zeroing mask"));
    }
    expected.extend(MEASURED_PROFILES.map(|config| format!("profile {config}")));
    expected.sort();
    assert_eq!(kat.section_names(), expected);
}

/// The configurations of the equal workload the summary describes.
const MEASURED_PROFILES: [&str; 3] = [
    "bgv.derive.n14.t257.q13x50.p2x60.d2/sparse128",
    "bgv.derive.n16.t786433.q25x60.p3x60.d2/split65536",
    "bgv.f257.n16.q22x50.p2x60/sparse128",
];

#[test]
fn the_shape_section_is_the_shape_of_the_costing_harness() {
    let kat = Kat::parse(VIEW);
    let section = Checked::new(&kat, "shape");
    section.expect_size("registers", REGISTERS);
    section.expect_size("state_lanes", STATE_LANES);
    section.expect_size("input_slots", INPUT_SLOTS);
    section.expect_size("max_instructions", MAX_INSTRUCTIONS);
    section.expect_size("max_outputs", MAX_OUTPUTS);
    section.expect_size("bounded_max_rank", BOUNDED_MAX_RANK);
    section.expect_size("select_multiplications", SELECT_MULTIPLICATIONS);
    // The refresh limits have no use in this crate yet; the script checks them against the
    // contract. They are pinned here so that a change is seen in both places.
    section.expect("refresh_max_rank_between_refreshes", 16);
    section.expect("refresh_max_refreshes", 64);
    section.expect_size(
        "largest_main_primes_of_the_implementation",
        MAX_BASIS_PRIMES - 2,
    );
    assert_eq!(section.text("opcodes"), OPCODE_NAMES.join(","));
    section.finish();
}

#[test]
fn candidate_geometry_sizes_work_units_and_contract_inputs_are_those_of_the_crate() {
    let kat = Kat::parse(VIEW);
    let mut profiles = Profiles::default();
    for candidate in BgvCandidate::ALL {
        let name = format!("candidate {}", candidate.name());
        let section = Checked::new(&kat, &name);
        let shape = read_shape(&section);
        assert_eq!(shape, shape_of(candidate), "{name}");
        // The derivation rule gives the pinned tables.
        assert_eq!(shape.parameters(), candidate.parameters(), "{name}");
        let profile = profiles.get(shape);
        assert_eq!(section.text("identity"), hex(profile.identity()), "{name}");
        assert_eq!(section.text("intended_class"), intended_class(candidate));
        check_profile_lines(&section, profile);
        // The values proposed for the open inputs of the resource contract.
        let model = CostModel::new(profile);
        let encoding = SlotEncoding::new(profile).expect("encoding");
        let top = profile.top_level();
        let broadcast = encoding.broadcast_elements().len() as u64;
        let units = |value: Result<u64, BgvError>| value.expect("units");
        section.expect(
            "contract.ram_lfe.ciphertext_bytes",
            units(model.ciphertext_bytes(top, 2)),
        );
        section.expect_size(
            "contract.ram_lfe.input_ciphertexts",
            INPUT_SLOTS.div_ceil(encoding.slots()),
        );
        section.expect_size(
            "contract.ram_lfe.output_ciphertexts",
            MAX_OUTPUTS.div_ceil(encoding.slots()),
        );
        section.expect(
            "contract.ram_lfe.evaluation_key_bytes",
            model.evaluation_key_bytes(encoding.broadcast_elements().len()),
        );
        section.expect(
            "contract.ram_lfe.multiplication_work_units",
            units(model.multiplication_units(top)),
        );
        // The costliest affine instruction of the lowering, from the harness itself.
        let (_, _, ledger) =
            fitting(plan_tape(profile, &instruction_profile(candidate)).expect("plan"));
        let costliest_affine = (0..OPCODE_NAMES.len())
            .filter(|tag| ![8, 9].contains(tag))
            .map(|tag| ledger.costliest[tag].units)
            .max()
            .expect("opcodes");
        assert_eq!(costliest_affine, ledger.costliest[0].units, "{name}");
        assert_eq!(
            costliest_affine,
            units(model.plaintext_multiplication_units(top))
                + broadcast * units(model.automorphism_units(top)),
            "{name}"
        );
        section.expect(
            "contract.ram_lfe.plain_operation_work_units",
            costliest_affine,
        );
        section.expect(
            "proposed.ram_lfe.key_switch_work_units",
            units(model.key_switch_units(top)),
        );
        section.expect(
            "proposed.ram_lfe.plaintext_multiplication_work_units",
            units(model.plaintext_multiplication_units(top)),
        );
        section.expect(
            "proposed.ram_lfe.modulus_switch_work_units",
            units(model.switch_down_units(top)),
        );
        section.expect("proposed.ram_lfe.input_load_key_switches", broadcast);
        // The budget formulas of the contract against the planned families that fit.
        let planned: Vec<(&str, bool, u64)> = candidate_families(candidate)
            .into_iter()
            .filter_map(
                |(family, tape)| match plan_tape(profile, &tape).expect("plan") {
                    TapePlan::Fits { ledger, .. } => Some((
                        family,
                        tape.iter().all(Instruction::is_affine),
                        ledger.total.units,
                    )),
                    TapePlan::Refused { .. } => None,
                },
            )
            .collect();
        let mut budgets = vec![(
            "ram_lfe.affine_evaluation_work_units",
            MAX_INSTRUCTIONS as u64 * costliest_affine,
            true,
        )];
        if candidate != BgvCandidate::AffineF257 {
            budgets.push((
                "ram_lfe.bounded_evaluation_work_units",
                (MAX_INSTRUCTIONS * SELECT_MULTIPLICATIONS) as u64
                    * units(model.multiplication_units(top)),
                false,
            ));
        }
        for (budget, value, affine_only) in budgets {
            let (family, _, largest) = planned
                .iter()
                .filter(|(_, affine, _)| *affine || !affine_only)
                .max_by_key(|(_, _, units)| *units)
                .expect("a family fits");
            section.expect(&format!("budget.{budget}.formula_value"), value);
            assert_eq!(
                section.text(&format!("budget.{budget}.largest_planned_family")),
                *family
            );
            section.expect(
                &format!("budget.{budget}.largest_planned_work_units"),
                *largest,
            );
            assert_eq!(
                section.flag(&format!("budget.{budget}.covers")),
                *largest <= value,
                "{name} {budget}"
            );
        }
        section.finish();
    }
}

#[test]
fn measured_profile_geometry_and_the_shortest_chain_of_the_equal_workload() {
    let kat = Kat::parse(VIEW);
    let mut profiles = Profiles::default();
    for config in MEASURED_PROFILES {
        let name = format!("profile {config}");
        let section = Checked::new(&kat, &name);
        let shape = read_shape(&section);
        check_profile_lines(&section, profiles.get(shape));
        // The workload fits the recorded chain and not one prime less.
        let minimal = usize::try_from(section.number("minimal_main_primes_for_equal_workload"))
            .expect("count");
        assert!(minimal <= shape.main.1, "{name}");
        assert!(
            equal_workload_fits(profiles.get(shape.with_main_primes(minimal))),
            "{name}: the workload does not fit {minimal} main primes"
        );
        assert!(
            !equal_workload_fits(profiles.get(shape.with_main_primes(minimal - 1))),
            "{name}: the workload already fits {} main primes",
            minimal - 1
        );
        section.finish();
    }
}

#[test]
fn instruction_costs_and_longest_chains_are_those_of_the_harness() {
    let kat = Kat::parse(VIEW);
    let mut profiles = Profiles::default();
    for candidate in BgvCandidate::ALL {
        let shape = shape_of(candidate);
        let profile = profiles.get(shape);
        let tape = instruction_profile(candidate);
        let (_, _, ledger) = fitting(plan_tape(profile, &tape).expect("plan"));
        for (tag, opcode) in OPCODE_NAMES.iter().enumerate() {
            if ledger.instructions[tag] == 0 {
                continue;
            }
            let name = format!("instruction {} {opcode}", candidate.name());
            let section = Checked::new(&kat, &name);
            expect_work(&section, ledger.costliest[tag]);
            section.finish();
        }
        let name = format!("instruction {} final zeroing mask", candidate.name());
        let section = Checked::new(&kat, &name);
        expect_work(&section, ledger.by_opcode[11]);
        section.finish();

        // The longest chain of constant multiplications beside 64 outputs, per rank.
        let name = format!("frontier {}", candidate.name());
        let section = Checked::new(&kat, &name);
        let ranks: &[usize] = if candidate == BgvCandidate::AffineF257 {
            &[0]
        } else {
            &[0, SELECT_MULTIPLICATIONS, BOUNDED_MAX_RANK]
        };
        for &rank in ranks {
            let limit = MAX_INSTRUCTIONS - 1 - rank - MAX_OUTPUTS;
            section.expect_size(&format!("after_rank_{rank}.instruction_limit"), limit);
            let recorded =
                usize::try_from(section.number(&format!("after_rank_{rank}"))).expect("count");
            assert!(recorded <= limit, "{name} rank {rank}");
            let chain = |scales: usize| families::frontier(rank, scales, MAX_OUTPUTS);
            assert!(
                fits(profile, &chain(recorded), None),
                "{name} rank {rank}: {recorded} do not fit"
            );
            assert!(
                recorded == limit || !fits(profile, &chain(recorded + 1), None),
                "{name} rank {rank}: {} fit",
                recorded + 1
            );
        }
        section.finish();
    }
}

#[test]
fn every_family_plan_is_the_shape_run_of_the_harness() {
    let kat = Kat::parse(VIEW);
    let mut profiles = Profiles::default();
    for candidate in BgvCandidate::ALL {
        let shape = shape_of(candidate);
        for (family, tape) in candidate_families(candidate) {
            let name = format!("tape {} {family}", candidate.name());
            let section = Checked::new(&kat, &name);
            let profile = profiles.get(shape);
            let plan = plan_tape(profile, &tape).expect("plan");
            assert_eq!(section.flag("fits"), plan.fits(), "{name}");
            let mut output_bound = None;
            match plan {
                TapePlan::Fits {
                    output,
                    capacity_bits,
                    ledger,
                } => {
                    section.expect_size("output_level", output.level());
                    section.expect_size("output_noise_bound_bits", output.bound_bits());
                    section.expect_size("output_capacity_bits", capacity_bits);
                    expect_work(&section, ledger.total);
                    section.expect(
                        "peak_persistent_ciphertext_bytes",
                        ledger.peak_persistent_bytes,
                    );
                    section.expect("peak_working_bytes", ledger.peak_working_bytes);
                    output_bound = Some((output.bound().clone(), output.level()));
                }
                TapePlan::Refused { instruction, tag } => {
                    section.expect_size("refused_at_instruction", instruction);
                    let opcode = OPCODE_NAMES
                        .get(tag)
                        .copied()
                        .unwrap_or("final zeroing mask");
                    assert_eq!(section.text("refused_opcode"), opcode, "{name}");
                }
            }
            check_minimal(
                &mut profiles,
                shape,
                &tape,
                None,
                section.optional("minimal_main_primes"),
                &name,
            );
            // The two illustrative flooding settings the summary projects.
            for (releases, kappa) in [(20_u32, 80_u32), (20, 40)] {
                let prefix = format!("flooding.{releases}.{kappa}");
                let profile = profiles.get(shape);
                let flooded = output_bound.as_ref().map(|(bound, level)| {
                    (
                        flooded_bound(profile, bound, releases, kappa),
                        profile.capacity(*level).expect("capacity").clone(),
                    )
                });
                assert_eq!(
                    section.flag(&format!("{prefix}.fits")),
                    flooded
                        .as_ref()
                        .is_some_and(|(bound, capacity)| bound <= capacity),
                    "{name} {prefix}"
                );
                let bits_key = format!("{prefix}.noise_bound_bits");
                assert_eq!(section.has(&bits_key), flooded.is_some(), "{name} {prefix}");
                if let Some((bound, _)) = &flooded {
                    section.expect_size(&bits_key, bound.bit_len());
                }
                check_minimal(
                    &mut profiles,
                    shape,
                    &tape,
                    Some((releases, kappa)),
                    section.optional(&format!("{prefix}.minimal_main_primes")),
                    &format!("{name} {prefix}"),
                );
            }
            section.finish();
        }
    }
}

#[test]
fn the_refresh_room_projection_is_planned_by_the_harness() {
    let kat = Kat::parse(VIEW);
    let mut profiles = Profiles::default();
    let section = Checked::new(&kat, "refresh room");
    let shape = shape_of(BgvCandidate::RefreshF257);
    let segment_name = section.text("segment_family");
    let segment = families::all()
        .into_iter()
        .find(|(_, name, _)| *name == segment_name)
        .map(|(_, _, tape)| tape)
        .expect("family");
    check_minimal(
        &mut profiles,
        shape,
        &segment,
        None,
        Some(section.number("main_primes_of_the_segment")),
        "segment",
    );
    // The cited depth is ceil(log2(2N/3) + log2(t)): the weight of a uniform ternary secret
    // lies between 2^15 and 2^16 and t between 2^8 and 2^9, so the sum of the logarithms
    // lies between 23 and 25; the recorded 24 is checked against exact powers of two.
    let depth = usize::try_from(section.number("cited_bootstrapping_depth")).expect("depth");
    let weight = 2 * (1_u128 << shape.log_degree) / 3;
    let product = weight * u128::from(shape.plaintext_modulus);
    assert!(product > 1 << (depth - 1) && product <= 1 << depth);
    check_minimal(
        &mut profiles,
        shape,
        &families::frontier(depth, 0, 1),
        None,
        section.optional("main_primes_of_a_chain_of_that_depth"),
        "depth chain",
    );
    section.finish();
}
