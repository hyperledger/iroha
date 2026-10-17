//! Exact wrapping effective-address equations for the unfinished memory relation.
//!
//! The two existing 64-bit Boolean source words hold the base and effective
//! address. Two additional signed carries prove the low/high 32-bit additions.
//! This unregistered component does not authenticate its instruction, source
//! register, privacy tag, enable/phase owner, access permission or memory effect.
//! The 128-bit opcodes preserve the entire base address and use no immediate;
//! the final operand byte names the high data register instead.
// TODO: Link the instruction and both words to the unified fetch/register/request
// schedule, including exact native trap priority, before any proof admission.

use super::{F, Sources, wide, word};

pub(super) const WIDTH: usize = 2;
pub(super) const CONSTRAINTS: usize = word::WIDTH + 4;
const RADIX: u64 = 1 << 32;

/// Memory opcode semantics derived from one still-unauthenticated instruction.
#[derive(Clone, Copy)]
pub(super) struct Operation {
    immediate: i8,
}

impl Operation {
    pub(super) fn from_word(instruction: u32) -> Option<Self> {
        match wide::opcode(instruction) {
            wide::memory::LOAD64 | wide::memory::STORE64 => Some(Self {
                immediate: wide::imm8(instruction),
            }),
            wide::memory::LOAD128 | wide::memory::STORE128 => Some(Self { immediate: 0 }),
            _ => None,
        }
    }

    fn immediate_field(self) -> F {
        if self.immediate < 0 {
            F::ZERO.sub(F(u64::from(self.immediate.unsigned_abs())))
        } else {
            F(self.immediate as u64)
        }
    }
}

fn signed_field(value: i128) -> F {
    if value < 0 {
        F::ZERO.sub(F((-value) as u64))
    } else {
        F(value as u64)
    }
}

/// Candidate carries only; the evaluator owns their range and both equalities.
pub(super) fn witness(base: u64, operation: Operation) -> [F; WIDTH] {
    let low = i128::from(base & u64::from(u32::MAX)) + i128::from(operation.immediate);
    let low_carry = low.div_euclid(i128::from(RADIX));
    let high = i128::from(base >> 32) + low_carry;
    let high_carry = high.div_euclid(i128::from(RADIX));
    [signed_field(low_carry), signed_field(high_carry)]
}

pub(super) fn append_residues(
    out: &mut Vec<F>,
    sources: Sources<'_>,
    carries: &[F; WIDTH],
    operation: Operation,
) {
    let start = out.len();
    sources.append_residues(out);
    // Signed carry values are exactly -1, 0 or 1. Each limb equation has
    // integer magnitude below 2*2^32+128, so field zero cannot hide a p-offset.
    for carry in carries {
        out.push(carry.mul(carry.sub(F::ONE)).mul(carry.add(F::ONE)));
    }
    out.push(
        sources
            .half(0, 0)
            .add(operation.immediate_field())
            .sub(sources.half(1, 0))
            .sub(carries[0].mul(F(RADIX))),
    );
    out.push(
        sources
            .half(0, 1)
            .add(carries[0])
            .sub(sources.half(1, 1))
            .sub(carries[1].mul(F(RADIX))),
    );
    debug_assert_eq!(out.len() - start, CONSTRAINTS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    use ivm::{IVM, Memory, ProgramMetadata, encoding::wide as enc, ivm_mode};

    fn residues(bits: &[F], carries: &[F; WIDTH], operation: Operation) -> Vec<F> {
        let mut out = Vec::new();
        append_residues(&mut out, Sources::new(bits), carries, operation);
        assert_eq!(out.len(), CONSTRAINTS);
        out
    }

    fn accepts(bits: &[F], carries: &[F; WIDTH], operation: Operation) -> bool {
        residues(bits, carries, operation)
            .into_iter()
            .all(|x| x == F::ZERO)
    }

    fn operation(opcode: u8, last: u8) -> Operation {
        Operation::from_word(enc::encode_rr(opcode, 1, 3, last)).unwrap()
    }

    #[test]
    fn every_signed_immediate_and_limb_boundary_has_unique_wrapping_carries() {
        let bases = [
            0,
            1,
            127,
            128,
            255,
            u64::from(u32::MAX) - 127,
            u64::from(u32::MAX),
            RADIX,
            RADIX + 127,
            (1 << 63) - 1,
            1 << 63,
            u64::MAX - 127,
            u64::MAX - 1,
            u64::MAX,
        ];
        for base in bases {
            for immediate in i8::MIN..=i8::MAX {
                for opcode in [wide::memory::LOAD64, wide::memory::STORE64] {
                    let op = operation(opcode, i8::cast_unsigned(immediate));
                    // Independent machine-integer oracle, not the carry witness formula.
                    let effective = i64::cast_unsigned(
                        u64::cast_signed(base).wrapping_add(i64::from(immediate)),
                    );
                    let bits = word::witness(base, effective);
                    let carries = witness(base, op);
                    assert!(accepts(&bits, &carries, op), "base={base} imm={immediate}");
                    for a in [-1_i128, 0, 1] {
                        for b in [-1_i128, 0, 1] {
                            let candidate = [signed_field(a), signed_field(b)];
                            assert_eq!(accepts(&bits, &candidate, op), candidate == carries);
                        }
                    }
                }
                for opcode in [wide::memory::LOAD128, wide::memory::STORE128] {
                    let op = operation(opcode, i8::cast_unsigned(immediate));
                    assert!(accepts(&word::witness(base, base), &witness(base, op), op));
                    assert_eq!(witness(base, op), [F::ZERO; WIDTH]);
                }
            }
        }
    }

    #[test]
    fn every_address_bit_and_signed_carry_rejects_mutation() {
        for (base, immediate) in [(0, -1_i8), (u64::MAX, 1), (RADIX - 1, 127), (RADIX, -128)] {
            let op = operation(wide::memory::LOAD64, i8::cast_unsigned(immediate));
            let effective = base.wrapping_add_signed(i64::from(immediate));
            let bits = word::witness(base, effective);
            let carries = witness(base, op);
            for index in 0..word::WIDTH {
                let mut changed = bits;
                changed[index] = F::ONE.sub(changed[index]);
                assert!(!accepts(&changed, &carries, op), "bit {index}");
                changed[index] = F(2);
                assert!(!accepts(&changed, &carries, op));
            }
            for index in 0..WIDTH {
                for value in [
                    signed_field(-2),
                    signed_field(-1),
                    F::ZERO,
                    F::ONE,
                    F(2),
                    F(1 << 31),
                ] {
                    if value == carries[index] {
                        continue;
                    }
                    let mut changed = carries;
                    changed[index] = value;
                    assert!(!accepts(&bits, &changed, op));
                }
            }
        }
    }

    #[test]
    fn memory_opcode_selects_imm8_but_wide_high_register_is_not_an_immediate() {
        assert!(Operation::from_word(enc::encode_rr(wide::arithmetic::ADD, 1, 3, 127)).is_none());
        let base = RADIX + 256;
        for last in 1..=u8::MAX {
            let scalar = operation(wide::memory::LOAD64, last);
            let wide = operation(wide::memory::LOAD128, last);
            let shifted = base.wrapping_add_signed(i64::from(u8::cast_signed(last)));
            assert!(!accepts(
                &word::witness(base, shifted),
                &witness(base, wide),
                wide
            ));
            assert!(!accepts(
                &word::witness(base, base),
                &witness(base, scalar),
                scalar
            ));
        }
    }

    #[test]
    fn coherent_foreign_inputs_demonstrate_the_missing_outer_linkage() {
        let base = Memory::HEAP_START + 128;
        let first = operation(wide::memory::LOAD64, 8);
        let foreign = operation(wide::memory::STORE64, 16);
        assert!(accepts(
            &word::witness(base, base + 8),
            &witness(base, first),
            first
        ));
        assert!(accepts(
            &word::witness(base + 64, base + 80),
            &witness(base + 64, foreign),
            foreign,
        ));
        assert!(!accepts(
            &word::witness(base, base + 80),
            &witness(base, first),
            first,
        ));
        // A valid address equation is deliberately not instruction/register
        // authority: the unified fetch and packet relation must reject the
        // entire otherwise-valid foreign input above.
    }

    fn native(words: &[u32]) -> IVM {
        let mut bytes = ProgramMetadata {
            mode: ivm_mode::ZK | ivm_mode::VECTOR,
            max_cycles: 2,
            ..ProgramMetadata::default()
        }
        .encode();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let mut vm = IVM::new(100);
        vm.load_program(&bytes).unwrap();
        vm
    }

    #[test]
    fn address_equations_match_native_signed_offsets_wrap_and_full_wide_values() {
        let address = Memory::HEAP_START + 256;
        let value = 0xfedc_ba98_7654_3210_u64;
        for immediate in [-128_i8, -127, -1, 0, 1, 63, 126, 127] {
            for store in [false, true] {
                let word = if store {
                    enc::encode_store(wide::memory::STORE64, 3, 1, immediate)
                } else {
                    enc::encode_load(wide::memory::LOAD64, 1, 3, immediate)
                };
                let base = address.wrapping_sub(i64::cast_unsigned(i64::from(immediate)));
                let op = Operation::from_word(word).unwrap();
                assert!(accepts(
                    &word::witness(base, address),
                    &witness(base, op),
                    op
                ));
                let mut vm = native(&[word, enc::encode_halt()]);
                vm.set_register(3, base);
                if store {
                    vm.set_register(1, value);
                } else {
                    vm.memory.store_u64(address, value).unwrap();
                }
                vm.run().unwrap();
                assert_eq!(vm.memory.load_u64(address).unwrap(), value);
                assert_eq!(vm.registers.get(1), value);
                assert!(!vm.registers.tag(1));
                assert_eq!(
                    (vm.pc(), vm.get_cycle_count(), vm.gas_remaining),
                    (8, 2, 97)
                );
            }
        }
        for (base, imm) in [(u64::MAX, 1_i8), (u64::MAX - 7, 8)] {
            let word = enc::encode_load(wide::memory::LOAD64, 1, 3, imm);
            let op = Operation::from_word(word).unwrap();
            assert!(accepts(&word::witness(base, 0), &witness(base, op), op));
            let mut vm = native(&[word, enc::encode_halt()]);
            let code = vm.memory.load_u64(0).unwrap();
            vm.set_register(3, base);
            vm.run().unwrap();
            assert_eq!(vm.registers.get(1), code);
        }
        let full = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef_u128;
        for high in [2, 127, 128, 255] {
            for store in [false, true] {
                let word = if store {
                    enc::encode_store128(wide::memory::STORE128, 3, 1, high)
                } else {
                    enc::encode_load128(wide::memory::LOAD128, 1, 3, high)
                };
                let op = Operation::from_word(word).unwrap();
                assert!(accepts(
                    &word::witness(address, address),
                    &witness(address, op),
                    op
                ));
                let mut vm = native(&[word, enc::encode_halt()]);
                vm.set_register(3, address);
                if store {
                    vm.set_register(1, full as u64);
                    vm.set_register(usize::from(high), (full >> 64) as u64);
                } else {
                    vm.memory.store_u128(address, full).unwrap();
                }
                vm.run().unwrap();
                assert_eq!(vm.memory.load_u128(address).unwrap(), full);
                assert_eq!(
                    (u128::from(vm.registers.get(usize::from(high))) << 64)
                        | u128::from(vm.registers.get(1)),
                    full
                );
                assert_eq!(
                    (vm.pc(), vm.get_cycle_count(), vm.gas_remaining),
                    (8, 2, 95)
                );
            }
        }
    }

    #[test]
    fn address_bank_uses_two_fields_and_has_exact_degree_three() {
        assert_eq!(WIDTH, 2);
        assert_eq!(CONSTRAINTS, 132);
        for opcode in [
            wide::memory::LOAD64,
            wide::memory::STORE64,
            wide::memory::LOAD128,
            wide::memory::STORE128,
        ] {
            let op = operation(opcode, 128);
            assert_eq!(
                measured_maximum_affine_degree_v1(
                    [opcode; 32],
                    [word::WIDTH + WIDTH, 0, 0, 0, 0],
                    4,
                    3,
                    |row, _, _, _, _| {
                        let carries = [row[word::WIDTH], row[word::WIDTH + 1]];
                        Ok::<_, core::convert::Infallible>(residues(
                            &row[..word::WIDTH],
                            &carries,
                            op,
                        ))
                    }
                ),
                3
            );
        }
        // Conditional geometry only: two additional fields under the unchanged
        // 136-query/two-DEEP-point encoding cost exactly 4480 bytes. This is not
        // a new integrated profile, which still needs request/owner linkage.
        assert_eq!(WIDTH * (136 * 2 * 8 + 2 * 32), 4480);
    }
}
