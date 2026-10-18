//! Original bounded region, selected privacy bytes and atomic register effect.

use super::*;
const ADDRESS_WORD: usize = 0;
const END: usize = 1;
const STACK_TOP: usize = 2;
const HEAP_END: usize = 3;
const CODE_LEN: usize = 4;
const CARRIES: usize = 5 * 64;
const COMPARES: usize = CARRIES + 4;
const COMPARE_WIDTH: usize = 68;
const FLAGS: usize = COMPARES + 14 * COMPARE_WIDTH;
const CODE: usize = FLAGS;
const HEAP: usize = FLAGS + 1;
const INPUT: usize = FLAGS + 2;
const OUTPUT: usize = FLAGS + 3;
const STACK: usize = FLAGS + 4;
const MASK: usize = FLAGS + 5;
const SELECTED_MASK: usize = MASK + 16;
const ZERO_INVERSE: usize = SELECTED_MASK + 8;
const FULL_INVERSE: usize = ZERO_INVERSE + 1;
const LOG: usize = FULL_INVERSE + 1;
pub(super) const WIDTH: usize = LOG + 4;
/// Exact fixed-bank census, asserted on every construction and residue evaluation.
pub(super) const CONSTRAINTS: usize = 1879;

fn pack(bits: &[F]) -> F {
    bits.iter()
        .enumerate()
        .fold(F::ZERO, |a, (i, &b)| a.add(b.mul(F(1 << i))))
}
fn word(row: &[F], index: usize) -> &[F] {
    &row[index * 64..(index + 1) * 64]
}
fn limb(row: &[F], index: usize, i: usize) -> F {
    pack(&word(row, index)[i * 16..(i + 1) * 16])
}
fn constant(value: u64, selected: F) -> [F; 64] {
    core::array::from_fn(|i| selected.mul(F((value >> i) & 1)))
}
fn operands(row: &[F], i: usize, selected: F) -> ([F; 64], [F; 64]) {
    let w = |i| word(row, i).try_into().unwrap();
    let c = |v| constant(v, selected);
    match i {
        0 => (w(ADDRESS_WORD), c(ivm::Memory::HEAP_START)),
        1 => (w(HEAP_END), w(END)),
        2 => (w(ADDRESS_WORD), c(ivm::Memory::INPUT_START)),
        3 => (
            c(ivm::Memory::INPUT_START + ivm::Memory::INPUT_SIZE),
            w(END),
        ),
        4 => (w(ADDRESS_WORD), c(ivm::Memory::OUTPUT_START)),
        5 => (
            c(ivm::Memory::OUTPUT_START + ivm::Memory::OUTPUT_SIZE),
            w(END),
        ),
        6 => (w(ADDRESS_WORD), c(ivm::Memory::STACK_START)),
        7 => (w(STACK_TOP), w(END)),
        8 => (w(CODE_LEN), w(END)),
        9 => (w(HEAP_END), c(ivm::Memory::HEAP_START)),
        10 => (c(ivm::Memory::INPUT_START), w(HEAP_END)),
        11 => (c(ivm::Memory::HEAP_START), w(CODE_LEN)),
        12 => (w(STACK_TOP), c(ivm::Memory::STACK_START)),
        13 => (
            c(ivm::Memory::STACK_START + ivm::Memory::STACK_SIZE),
            w(STACK_TOP),
        ),
        _ => unreachable!("closed LOAD region comparisons"),
    }
}

pub(super) fn append_residues(out: &mut Vec<F>, schedule: Schedule, row: &[F; super::WIDTH]) {
    let start = out.len();
    let selected = row[CARRY + LOAD];
    let memory = port(row, 0);
    let destination = row[CARRY + DESTINATION];
    let enabled = row[CARRY + DESTINATION_ENABLED];
    for &value in &row[..CARRIES] {
        out.push(bit(value));
        out.push(F::ONE.sub(selected).mul(value));
    }
    for i in 0..4 {
        out.push(limb(row, ADDRESS_WORD, i).sub(row[CARRY + ADDRESS + i]));
    }
    for (i, w) in [STACK_TOP, HEAP_END, CODE_LEN].into_iter().enumerate() {
        for j in 0..4 {
            out.push(limb(row, w, j).sub(carry_port(row, POLICY + i * packet::WIDTH)[BEFORE + j]));
        }
    }
    let mut less = [F::ZERO; 14];
    for (i, less) in less.iter_mut().enumerate() {
        let (a, b) = operands(row, i, selected);
        let bank = &row[COMPARES + i * COMPARE_WIDTH..COMPARES + (i + 1) * COMPARE_WIDTH];
        for &v in bank {
            out.push(bit(v));
        }
        for j in 0..4 {
            let borrow = if j == 0 { F::ZERO } else { bank[64 + j - 1] };
            out.push(
                pack(&a[j * 16..(j + 1) * 16])
                    .sub(pack(&b[j * 16..(j + 1) * 16]))
                    .sub(borrow)
                    .sub(pack(&bank[j * 16..(j + 1) * 16]))
                    .add(bank[64 + j].mul(F(1 << 16))),
            );
        }
        *less = bank[67];
    }
    out.push(bit(row[CODE]));
    out.push(row[CODE].sub(selected.mul(F::ONE.sub(less[8]))));
    for (flag, a, b) in [(HEAP, 0, 1), (INPUT, 2, 3), (OUTPUT, 4, 5), (STACK, 6, 7)] {
        out.push(bit(row[flag]));
        out.push(row[flag].sub(selected.mul(F::ONE.sub(less[a])).mul(F::ONE.sub(less[b]))));
    }
    out.push(
        selected
            .sub(row[CODE])
            .sub(row[HEAP])
            .sub(row[INPUT])
            .sub(row[OUTPUT])
            .sub(row[STACK]),
    );
    for i in 9..14 {
        out.push(less[i]);
    }
    for &v in &word(row, ADDRESS_WORD)[..3] {
        out.push(v);
    }
    for i in 0..4 {
        let old = if i == 0 {
            F::ZERO
        } else {
            row[CARRIES + i - 1]
        };
        let addend = if i == 0 { selected.mul(F(8)) } else { F::ZERO };
        out.push(bit(row[CARRIES + i]));
        out.push(
            limb(row, ADDRESS_WORD, i)
                .add(addend)
                .add(old)
                .sub(limb(row, END, i))
                .sub(row[CARRIES + i].mul(F(1 << 16))),
        );
    }
    out.push(row[CARRIES + 3]);
    let cell = pack(&word(row, ADDRESS_WORD)[4..36]);
    for &v in &word(row, ADDRESS_WORD)[36..] {
        out.push(v);
    }
    header(
        out,
        memory,
        schedule,
        Space::Memory,
        F::ZERO,
        cell,
        32,
        selected,
        F::ZERO,
    );
    link(out, &memory[AFTER..AFTER + 8], &memory[BEFORE..BEFORE + 8]);
    out.push(memory[AFTER_TAG].sub(memory[BEFORE_TAG]));
    let half = word(row, ADDRESS_WORD)[3];
    for i in 0..8 {
        let actual = row[SELECTED_MASK + i];
        out.push(bit(actual));
        out.push(
            actual.sub(
                selected
                    .sub(half)
                    .mul(row[MASK + i])
                    .add(half.mul(row[MASK + 8 + i])),
            ),
        );
    }
    for &v in &row[MASK..MASK + 16] {
        out.push(F::ONE.sub(selected).mul(v));
    }
    let count = row[SELECTED_MASK..SELECTED_MASK + 8]
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    let (zero, full) = super::super::super::memory_load::mask_flags(
        out,
        row[MASK..MASK + 16].try_into().unwrap(),
        memory[BEFORE_TAG],
        count,
        selected.mul(F(8)),
        row[ZERO_INVERSE],
        row[FULL_INVERSE],
    );
    let private = full.mul(row[STACK]);
    out.push(selected.sub(selected.mul(zero)).sub(private));
    let write = port(row, 1);
    header(
        out,
        write,
        schedule,
        Space::Register,
        F::ZERO,
        destination,
        33,
        enabled,
        enabled,
    );
    for i in 4..8 {
        out.push(write[BEFORE + i]);
    }
    for i in 0..8 {
        let value = if i >= 4 {
            F::ZERO
        } else {
            selected
                .sub(half)
                .mul(memory[BEFORE + i])
                .add(half.mul(memory[BEFORE + 4 + i]))
        };
        out.push(write[AFTER + i].sub(enabled.mul(value)));
    }
    out.push(bit(write[BEFORE_TAG]));
    out.push(write[AFTER_TAG].sub(enabled.mul(private)));
    for (actual, expected) in row[LOG..LOG + 4].iter().zip([
        pack(&word(row, ADDRESS_WORD)[..32]),
        pack(&word(row, ADDRESS_WORD)[32..]),
        selected.mul(F(8)),
        selected,
    ]) {
        out.push(actual.sub(expected));
    }
    assert_eq!(out.len() - start, CONSTRAINTS);
}

#[cfg(test)]
pub(super) fn witness(address: u64, selected: bool, policies: [u64; 3], mask: u16) -> [F; WIDTH] {
    let mut row = [F::ZERO; WIDTH];
    let s = F(u64::from(selected));
    let address = if selected { address } else { 0 };
    let policies = if selected { policies } else { [0; 3] };
    let end = address.wrapping_add(if selected { 8 } else { 0 });
    for (w, value) in [address, end, policies[0], policies[1], policies[2]]
        .into_iter()
        .enumerate()
    {
        for i in 0..64 {
            row[w * 64 + i] = F((value >> i) & 1);
        }
    }
    for i in 0..14 {
        let (a, b) = operands(&row, i, s);
        let mut borrow = 0i64;
        for j in 0..4 {
            let value = u64::cast_signed(pack(&a[j * 16..(j + 1) * 16]).0)
                - u64::cast_signed(pack(&b[j * 16..(j + 1) * 16]).0)
                - borrow;
            borrow = i64::from(value < 0);
            for k in 0..16 {
                row[COMPARES + i * 68 + j * 16 + k] =
                    F((value.rem_euclid(1 << 16) as u64 >> k) & 1);
            }
            row[COMPARES + i * 68 + 64 + j] = F(i64::cast_unsigned(borrow));
        }
    }
    let mut carry = 0;
    for i in 0..4 {
        let addend = if i == 0 && selected { 8 } else { 0 };
        carry = (((address >> (i * 16)) & 0xffff) + addend + carry) >> 16;
        row[CARRIES + i] = F(carry);
    }
    let in_region = |start, limit| selected && address >= start && end <= limit;
    row[CODE] = F(u64::from(in_region(0, policies[2])));
    row[HEAP] = F(u64::from(in_region(ivm::Memory::HEAP_START, policies[1])));
    row[INPUT] = F(u64::from(in_region(
        ivm::Memory::INPUT_START,
        ivm::Memory::INPUT_START + ivm::Memory::INPUT_SIZE,
    )));
    row[OUTPUT] = F(u64::from(in_region(
        ivm::Memory::OUTPUT_START,
        ivm::Memory::OUTPUT_START + ivm::Memory::OUTPUT_SIZE,
    )));
    row[STACK] = F(u64::from(in_region(ivm::Memory::STACK_START, policies[0])));
    for i in 0..16 {
        row[MASK + i] = F(u64::from(selected && mask & (1 << i) != 0));
    }
    let half = (address & 8) as usize;
    for i in 0..8 {
        row[SELECTED_MASK + i] = row[MASK + half + i];
    }
    let count = row[SELECTED_MASK..SELECTED_MASK + 8]
        .iter()
        .copied()
        .fold(F::ZERO, F::add);
    row[ZERO_INVERSE] = count.inv().unwrap_or(F::ZERO);
    row[FULL_INVERSE] = count.sub(s.mul(F(8))).inv().unwrap_or(F::ZERO);
    row[LOG] = F(address & 0xffff_ffff);
    row[LOG + 1] = F(address >> 32);
    row[LOG + 2] = s.mul(F(8));
    row[LOG + 3] = s;
    row
}
