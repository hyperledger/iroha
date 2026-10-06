//! The costing harness that lowers every V1 tape instruction onto RNS-BGV.
//!
//! `tests/support/machine.rs` holds one lowering of the eleven instructions
//! and two back ends for it: public shapes and real ciphertexts. These tests
//! establish what the cost model relies on:
//!
//! - the planned and the encrypted run of one tape agree, instruction by
//!   instruction, on the level and the noise bound of every register, every
//!   state lane and the output accumulator, and are refused at the same
//!   instruction when the chain is too short;
//! - the encrypted run computes the tape: every register decrypts to the
//!   scalar of an independent cleartext machine, broadcast to all slots, and
//!   the packed output holds the ordered outputs and zero elsewhere;
//! - the ledger charges each instruction the operations its lowering performs;
//! - the equality indicator `1 - x^256` is one exactly at zero for all 257
//!   field values under encryption;
//! - each maximum-shape tape family has the shape its name claims.
//!
//! Nothing here establishes security; the profiles are small arithmetic rings.
mod support;

use iroha_fhe::bgv::{
    BgvError, BgvParameters, BgvProfile, Ciphertext, CiphertextShape, EvaluationKeys, KeySet,
    SlotEncoding, cost::CostModel,
};
use support::machine::{
    BOUNDED_MAX_RANK, Backend, Cleartext, Encrypted, INPUT_SLOTS, Instruction, MAX_INSTRUCTIONS,
    MAX_OUTPUTS, Machine, OPCODE_NAMES, Planned, REGISTERS, STATE_LANES, TapePlan, Work, families,
    flooded_bound, peak_rank, plan_tape,
};

/// A ring of 128 sparse F257 slots with a chain long enough for one select and more.
fn profile(main_primes: usize) -> BgvProfile {
    BgvProfile::new(
        BgvParameters::derive(8, 257, (40, main_primes), (41, 3), 2).expect("parameters"),
    )
    .expect("profile")
}

/// The V1 input vector: slot 0 a length, then bytes, then zeros.
fn input_slots() -> Vec<u64> {
    let mut slots = vec![0_u64; INPUT_SLOTS];
    slots[0] = 40;
    for (index, slot) in slots.iter_mut().enumerate().skip(1).take(40) {
        *slot = (index as u64 * 37 + 11) % 256;
    }
    slots[5] = 0;
    slots[9] = 201;
    slots
}

fn initial_state() -> Vec<u64> {
    (0..STATE_LANES as u64)
        .map(|lane| (lane * 29 + 3) % 257)
        .collect()
}

/// A tape that uses every opcode, both branches of a select and every aliasing case.
fn coverage_tape() -> Vec<Instruction> {
    vec![
        // r0 = input[5] = 0, r1 = input[9] = 201, r2 = input[2].
        Instruction::LoadInput { dst: 0, slot: 5 },
        Instruction::LoadInput { dst: 1, slot: 9 },
        Instruction::LoadInput { dst: 2, slot: 2 },
        Instruction::Output { src: 1 },
        // r3 = 77; r3 = 77 + 200 = 20; r3 = 20 - 250 = 27.
        Instruction::LoadConst { dst: 3, value: 77 },
        Instruction::AddPlain {
            dst: 3,
            src: 3,
            value: 200,
        },
        Instruction::SubPlain {
            dst: 3,
            src: 3,
            value: 250,
        },
        // The zero branch: cond r0 = 0 selects r1; dst aliases the condition.
        Instruction::SelectEqZero {
            dst: 0,
            cond: 0,
            zero: 1,
            nonzero: 3,
        },
        Instruction::Output { src: 0 },
        Instruction::StoreState { lane: 7, src: 0 },
        // The non-zero branch: cond r1 = 201 selects r3; dst aliases a branch.
        Instruction::SelectEqZero {
            dst: 3,
            cond: 1,
            zero: 2,
            nonzero: 3,
        },
        Instruction::Output { src: 3 },
        // Products: a square in place, then a product of two registers.
        Instruction::Mul {
            dst: 2,
            lhs: 2,
            rhs: 2,
        },
        Instruction::MulPlain {
            dst: 2,
            src: 2,
            value: 256,
        },
        Instruction::LoadState { dst: 1, lane: 7 },
        Instruction::Mul {
            dst: 1,
            lhs: 1,
            rhs: 2,
        },
        Instruction::Output { src: 1 },
        // Sums across levels, an untouched initial lane and a register read before any write.
        Instruction::LoadState { dst: 0, lane: 31 },
        Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 0,
        },
        Instruction::Output { src: 0 },
        Instruction::Output { src: 2 },
    ]
}

struct Fixture {
    profile: BgvProfile,
    encoding: SlotEncoding,
    keys: KeySet,
    input: Ciphertext,
}

fn fixture(main_primes: usize) -> Fixture {
    let profile = profile(main_primes);
    let encoding = SlotEncoding::new(&profile).expect("encoding");
    let keys = KeySet::generate(&profile, &encoding.broadcast_elements()).expect("keys");
    let plaintext = encoding
        .encode(&profile, &input_slots())
        .expect("plaintext");
    let input = keys.public.encrypt(&profile, &plaintext).expect("input");
    Fixture {
        profile,
        encoding,
        keys,
        input,
    }
}

impl Fixture {
    fn encrypted(&self) -> Machine<'_, Encrypted<'_>> {
        let backend = Encrypted::new(&self.profile, &self.keys.evaluation, self.input.clone())
            .expect("back end");
        Machine::new(backend, &self.profile, &initial_state()).expect("machine")
    }

    fn planned(&self) -> Machine<'_, Planned<'_>> {
        let backend = Planned::new(&self.profile).expect("back end");
        Machine::new(backend, &self.profile, &initial_state()).expect("machine")
    }

    fn slots(&self, ciphertext: &Ciphertext) -> Vec<u64> {
        let plaintext = self
            .keys
            .secret
            .decrypt(&self.profile, ciphertext)
            .expect("plaintext");
        self.encoding.decode(&plaintext).expect("slots").to_vec()
    }
}

/// The shapes of every persistent value of a machine.
fn shapes<B: Backend>(machine: &Machine<'_, B>) -> Vec<CiphertextShape> {
    let backend = machine.backend();
    let mut shapes = vec![backend.shape(machine.input())];
    shapes.extend((0..REGISTERS).map(|index| backend.shape(machine.register(index))));
    shapes.extend((0..STATE_LANES).map(|index| backend.shape(machine.lane(index))));
    shapes.extend(machine.output().map(|value| backend.shape(value)));
    shapes
}

#[test]
fn both_back_ends_agree_on_every_instruction_and_the_run_computes_the_tape() {
    let fixture = fixture(22);
    let tape = coverage_tape();
    let used: std::collections::BTreeSet<usize> = tape.iter().map(Instruction::tag).collect();
    assert_eq!(used.len(), OPCODE_NAMES.len(), "the tape uses every opcode");
    let mut encrypted = fixture.encrypted();
    let mut planned = fixture.planned();
    let mut cleartext = Cleartext::new(&input_slots(), &initial_state());
    assert_eq!(shapes(&encrypted), shapes(&planned));
    for (index, instruction) in tape.iter().enumerate() {
        encrypted.step(*instruction).expect("encrypted step");
        planned.step(*instruction).expect("planned step");
        cleartext.step(*instruction);
        // Level, component count and noise bound of every live value.
        assert_eq!(shapes(&encrypted), shapes(&planned), "instruction {index}");
        assert_eq!(encrypted.ledger(), planned.ledger(), "instruction {index}");
        // Every register holds the cleartext scalar in all 128 slots.
        for register in 0..REGISTERS {
            assert_eq!(
                fixture.slots(encrypted.register(register)),
                vec![cleartext.registers[register]; 128],
                "instruction {index} register {register}"
            );
        }
    }
    for lane in [0, 7, 31] {
        assert_eq!(
            fixture.slots(encrypted.lane(lane)),
            vec![cleartext.state[lane]; 128],
            "lane {lane}"
        );
    }
    // Both select branches were taken and the outputs are the expected scalars.
    assert_eq!(cleartext.outputs, [201, 201, 27, 82, 169, 228]);
    let outputs = cleartext.outputs.len();
    assert_eq!(encrypted.outputs(), outputs);
    let (packed, encrypted_ledger) = encrypted.finish().expect("packed output");
    let (planned_output, planned_ledger) = planned.finish().expect("planned output");
    assert_eq!(packed.shape(), planned_output);
    assert_eq!(encrypted_ledger, planned_ledger);
    // The packed output: the ordered outputs in the first slots and zero elsewhere.
    let mut expected = cleartext.outputs.clone();
    expected.resize(128, 0);
    assert_eq!(fixture.slots(&packed), expected);
    // The one-call planner reports the same result.
    let plan = plan_tape(&fixture.profile, &tape).expect("plan");
    let TapePlan::Fits {
        output,
        capacity_bits,
        ledger,
    } = plan
    else {
        panic!("the tape fits 22 primes: {plan:?}");
    };
    // The planner starts every lane at the embedding of zero, which has the same shape.
    assert_eq!(output, planned_output);
    assert_eq!(*ledger, planned_ledger);
    assert_eq!(
        capacity_bits,
        fixture
            .profile
            .capacity(output.level())
            .expect("capacity")
            .bit_len()
    );
    assert!(output.bound_bits() <= capacity_bits);
}

#[test]
fn the_ledger_charges_each_instruction_the_operations_of_its_lowering() {
    let fixture = fixture(22);
    let model = CostModel::new(&fixture.profile);
    let top = fixture.profile.top_level();
    let mut machine = fixture.planned();
    // Before the first instruction: the input, four registers and 32 lanes at the top level.
    let ciphertext = model.ciphertext_residue_bytes(top, 2).expect("bytes");
    assert_eq!(machine.ledger().peak_persistent_bytes, 37 * ciphertext);
    for instruction in coverage_tape() {
        machine.step(instruction).expect("step");
    }
    let (_, ledger) = machine.finish().expect("output");
    // Instructions per opcode of the coverage tape, in tag order.
    assert_eq!(ledger.instructions, [3, 2, 1, 1, 2, 1, 1, 1, 2, 2, 6]);
    let load = ledger.by_opcode[0];
    // One mask multiplication and seven automorphisms per load, at the top level.
    assert_eq!(load.plaintext_multiplications, 3);
    assert_eq!(load.key_switches, 21);
    assert_eq!(load.multiplications, 0);
    assert_eq!(load.modulus_switches, 0);
    let one_load = model.plaintext_multiplication_units(top).expect("units")
        + 7 * model.automorphism_units(top).expect("units");
    assert_eq!(load.units, 3 * one_load);
    assert_eq!(ledger.costliest[0].units, one_load);
    assert_eq!(ledger.costliest[0].key_switches, 7);
    // Copies, constants and plaintext additions are not charged.
    for tag in [1, 2, 3, 5, 6] {
        assert_eq!(
            ledger.by_opcode[tag],
            Work::default(),
            "{}",
            OPCODE_NAMES[tag]
        );
    }
    // An addition is charged only the modulus switches that align its operands.
    assert_eq!(ledger.by_opcode[4].plaintext_multiplications, 0);
    assert_eq!(ledger.by_opcode[4].key_switches, 0);
    assert!(ledger.by_opcode[4].modulus_switches > 0);
    assert_eq!(ledger.by_opcode[7].plaintext_multiplications, 1);
    // One relinearized product per Mul and ten per SelectEqZero.
    assert_eq!(ledger.by_opcode[8].multiplications, 2);
    assert_eq!(ledger.by_opcode[8].key_switches, 2);
    assert_eq!(ledger.by_opcode[9].multiplications, 20);
    assert_eq!(ledger.costliest[9].multiplications, 10);
    assert!(ledger.by_opcode[9].modulus_switches > 0);
    // One mask multiplication per output and one more for the final zeroing mask.
    assert_eq!(ledger.by_opcode[10].plaintext_multiplications, 6);
    assert_eq!(ledger.by_opcode[11].plaintext_multiplications, 1);
    assert_eq!(
        ledger.by_opcode[11].units,
        ledger.total.units
            - ledger.by_opcode[..11]
                .iter()
                .map(|work| work.units)
                .sum::<u64>()
    );
    // The total is the sum over the opcodes.
    assert_eq!(
        ledger.total.multiplications,
        ledger
            .by_opcode
            .iter()
            .map(|work| work.multiplications)
            .sum::<u64>()
    );
    assert_eq!(ledger.total.key_switches, 21 + 22);
    assert_eq!(ledger.total.plaintext_multiplications, 3 + 1 + 6 + 1);
    // The output accumulator joins the persistent buffers; nothing exceeds 38 top ciphertexts.
    assert!(ledger.peak_persistent_bytes > 37 * ciphertext);
    assert!(ledger.peak_persistent_bytes <= 38 * ciphertext);
    // The working set adds the temporaries and the key-switch scratch of one operation.
    assert!(ledger.peak_working_bytes > ledger.peak_persistent_bytes);
    assert!(
        ledger.peak_working_bytes
            >= 37 * ciphertext + 8 * model.key_switch_scratch_words(top).expect("words")
    );
}

#[test]
fn a_chain_too_short_is_refused_at_the_same_instruction_by_both_back_ends() {
    // Eight 40-bit primes hold the loads and the first output but not a whole select.
    let fixture = fixture(8);
    let tape = coverage_tape();
    let plan = plan_tape(&fixture.profile, &tape).expect("plan");
    let TapePlan::Refused { instruction, tag } = plan else {
        panic!("eight primes cannot hold the tape: {plan:?}");
    };
    assert_eq!(tag, tape[instruction].tag());
    assert_eq!(OPCODE_NAMES[tag], "SelectEqZero");
    assert!(!plan.fits());
    let mut encrypted = fixture.encrypted();
    for (index, step) in tape.iter().enumerate() {
        let result = encrypted.step(*step);
        if index < instruction {
            assert_eq!(result, Ok(()), "instruction {index}");
        } else {
            assert!(
                matches!(
                    result,
                    Err(BgvError::NoiseBudgetExceeded { .. } | BgvError::NoLevelLeft)
                ),
                "instruction {index}: {result:?}"
            );
            break;
        }
    }
    // A chain that cannot hold a fresh ciphertext is refused before the first instruction.
    let narrow =
        BgvProfile::new(BgvParameters::derive(8, 257, (22, 1), (23, 1), 1).expect("parameters"))
            .expect("profile");
    assert_eq!(
        plan_tape(&narrow, &tape),
        Ok(TapePlan::Refused {
            instruction: 0,
            tag: 0
        })
    );
    // A tape without an output has nothing to pack.
    let mut machine = fixture.planned();
    machine
        .step(Instruction::LoadConst { dst: 0, value: 1 })
        .expect("step");
    assert_eq!(
        machine.finish().err(),
        Some(BgvError::SlotOutOfRange {
            index: 0,
            slots: MAX_OUTPUTS
        })
    );
}

/// The slot-wise indicator of zero for `values`, computed under encryption.
fn indicator(fixture: &Fixture, keys: &EvaluationKeys, values: &[u64]) -> Vec<u64> {
    let plaintext = fixture
        .encoding
        .encode(&fixture.profile, values)
        .expect("plaintext");
    let ciphertext = fixture
        .keys
        .public
        .encrypt(&fixture.profile, &plaintext)
        .expect("ciphertext");
    let backend = Encrypted::new(&fixture.profile, keys, ciphertext.clone()).expect("back end");
    let mut machine = Machine::new(backend, &fixture.profile, &[]).expect("machine");
    let top = fixture.profile.top_level();
    let one = machine.constant(1, top).expect("one");
    let zero = machine.constant(0, top).expect("zero");
    // nonzero + (1 - x^256) * (zero - nonzero) with branches one and zero is the indicator.
    let selected = machine.select(&ciphertext, &one, &zero).expect("select");
    fixture.slots(&selected)
}

#[test]
fn the_equality_indicator_is_one_exactly_at_zero_for_all_257_field_values() {
    let fixture = fixture(14);
    let keys = &fixture.keys.evaluation;
    // Every field element once, 128 per ciphertext: the full lowering of the equality
    // (eight squarings, the embedded one and the select product) on each of them.
    let all: Vec<u64> = (0..257).collect();
    let mut seen = 0_usize;
    for values in all.chunks(128) {
        let indicators = indicator(&fixture, keys, values);
        for (slot, &value) in values.iter().enumerate() {
            assert_eq!(indicators[slot], u64::from(value == 0), "value {value}");
            seen += 1;
        }
        // A slot the chunk left unused holds zero, whose indicator is one.
        assert!(indicators[values.len()..].iter().all(|&slot| slot == 1));
    }
    assert_eq!(seen, 257);
}

#[test]
fn every_family_has_the_maximum_shape_its_name_claims() {
    let count = |tape: &[Instruction], tag: usize| {
        tape.iter()
            .filter(|instruction| instruction.tag() == tag)
            .count()
    };
    let named = families::all();
    assert_eq!(named.len(), 9);
    for (class, name, tape) in &named {
        assert!(name.starts_with(class.trim_end_matches(".v1")), "{name}");
        assert!(!tape.is_empty() && tape.len() <= MAX_INSTRUCTIONS, "{name}");
        let outputs = count(tape, 10);
        assert!((1..=MAX_OUTPUTS).contains(&outputs), "{name}");
        let rank = peak_rank(tape);
        if *class == "affine.v1" {
            assert!(tape.iter().all(Instruction::is_affine), "{name}");
            assert_eq!(rank, 0, "{name}");
        } else {
            assert!(rank <= BOUNDED_MAX_RANK, "{name}: rank {rank}");
        }
        for instruction in tape {
            let in_range = match *instruction {
                Instruction::LoadInput { dst, slot } => dst < REGISTERS && slot < INPUT_SLOTS,
                Instruction::LoadState { dst, lane } => dst < REGISTERS && lane < STATE_LANES,
                Instruction::StoreState { lane, src } => src < REGISTERS && lane < STATE_LANES,
                Instruction::LoadConst { dst, value } => dst < REGISTERS && value < 257,
                Instruction::Add { dst, lhs, rhs } | Instruction::Mul { dst, lhs, rhs } => {
                    dst < REGISTERS && lhs < REGISTERS && rhs < REGISTERS
                }
                Instruction::AddPlain { dst, src, value }
                | Instruction::SubPlain { dst, src, value }
                | Instruction::MulPlain { dst, src, value } => {
                    dst < REGISTERS && src < REGISTERS && value < 257
                }
                Instruction::SelectEqZero {
                    dst,
                    cond,
                    zero,
                    nonzero,
                } => [dst, cond, zero, nonzero]
                    .iter()
                    .all(|&index| index < REGISTERS),
                Instruction::Output { src } => src < REGISTERS,
            };
            assert!(in_range, "{name}: {instruction:?}");
        }
    }
    let tape = |wanted: &str| {
        named
            .iter()
            .find(|(_, name, _)| *name == wanted)
            .map(|(_, _, tape)| tape.clone())
            .expect("family")
    };
    // The extremes of the V1 shape: 256 instructions, 255 loads, 255 selects, 64 outputs.
    let loads = tape("affine.loads");
    assert_eq!(
        (loads.len(), count(&loads, 0), count(&loads, 10)),
        (256, 255, 1)
    );
    let chain = tape("affine.scale_chain");
    assert_eq!((chain.len(), count(&chain, 7)), (256, 254));
    let scaled_outputs = tape("affine.scale_then_outputs");
    assert_eq!(
        (
            scaled_outputs.len(),
            count(&scaled_outputs, 7),
            count(&scaled_outputs, 10)
        ),
        (256, 191, 64)
    );
    let state = tape("affine.state_and_registers");
    assert_eq!(state.len(), 256);
    let used: std::collections::BTreeSet<usize> = state.iter().map(Instruction::tag).collect();
    assert_eq!(
        used.into_iter().collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5, 6, 10]
    );
    assert_eq!((count(&state, 2), count(&state, 10)), (32, 64));
    let selects = tape("bounded.selects");
    assert_eq!(
        (selects.len(), count(&selects, 9), peak_rank(&selects)),
        (256, 255, 10)
    );
    let scaled = tape("bounded.scaled_rank_chain");
    assert_eq!(
        (
            scaled.len(),
            count(&scaled, 7),
            count(&scaled, 8),
            peak_rank(&scaled)
        ),
        (256, 238, 16, 16)
    );
    let outputs = tape("bounded.rank_chain_outputs");
    assert_eq!(
        (count(&outputs, 8), count(&outputs, 10), peak_rank(&outputs)),
        (16, 64, 16)
    );
    let alternating = tape("bounded.alternating_rank_chain");
    assert_eq!(
        (
            count(&alternating, 7),
            count(&alternating, 8),
            peak_rank(&alternating)
        ),
        (17, 16, 16)
    );
    let select = tape("bounded.select_then_products");
    assert_eq!(
        (
            count(&select, 9),
            count(&select, 8),
            count(&select, 10),
            peak_rank(&select)
        ),
        (1, 6, 64, 16)
    );
    assert_eq!(families::frontier(3, 5, 2).len(), 1 + 3 + 5 + 2);
    assert_eq!(families::scale_chain(4, 1), families::frontier(0, 4, 1));
}

#[test]
fn the_flooding_projection_follows_its_formula() {
    let profile = profile(4);
    let t = 257_u64;
    let n = 256_u64;
    let fresh = profile.fresh_noise().to_u128().expect("fresh");
    for (bound, log2_releases, kappa) in [(1_u64, 0_u32, 0_u32), (257, 3, 5), (1_000_003, 20, 40)] {
        let error = u128::from(bound.div_ceil(t));
        let flood = (error * u128::from(n)) << (log2_releases + kappa);
        let expected = u128::from(bound) + flood * u128::from(t) + fresh;
        assert_eq!(
            flooded_bound(
                &profile,
                &iroha_fhe::natural::Natural::from_u64(bound),
                log2_releases,
                kappa
            )
            .to_u128(),
            Some(expected)
        );
    }
}
