//! Exact bounded region, byte, initialization and output-cursor success equations.

use super::*;
const WORDS: usize = 8;
const ADDRESS_WORD: usize = 0;
const END: usize = 1;
const STACK_TOP: usize = 2;
const HEAP_END: usize = 3;
const CODE_LEN: usize = 4;
const CURSOR: usize = 5;
const OFFSET: usize = 6;
const OUTPUT_END: usize = 7;
const CARRIES: usize = WORDS * 64;
const COMPARES: usize = CARRIES + 12;
const COMPARE_WIDTH: usize = 68;
const FLAGS: usize = COMPARES + 15 * COMPARE_WIDTH;
const HEAP: usize = FLAGS;
const OUTPUT: usize = FLAGS + 1;
const STACK: usize = FLAGS + 2;
const MEMORY_MASK: usize = FLAGS + 16;
const INITIAL_MASK: usize = MEMORY_MASK + 16;
const LOG: usize = INITIAL_MASK + 16;
pub(super) const WIDTH: usize = LOG + 12;
/// Exact fixed effect-bank equation census, independently checked by the held probe.
pub(super) const CONSTRAINTS: usize = 2573;

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
        2 => (w(ADDRESS_WORD), c(ivm::Memory::OUTPUT_START)),
        3 => (
            c(ivm::Memory::OUTPUT_START + ivm::Memory::OUTPUT_SIZE),
            w(END),
        ),
        4 => (w(ADDRESS_WORD), c(ivm::Memory::STACK_START)),
        5 => (w(STACK_TOP), w(END)),
        6 => (w(CODE_LEN), w(END)),
        7 => (w(HEAP_END), c(ivm::Memory::HEAP_START)),
        8 => (c(ivm::Memory::INPUT_START), w(HEAP_END)),
        9 => (c(ivm::Memory::HEAP_START), w(CODE_LEN)),
        10 => (w(STACK_TOP), c(ivm::Memory::STACK_START)),
        11 => (
            c(ivm::Memory::STACK_START + ivm::Memory::STACK_SIZE),
            w(STACK_TOP),
        ),
        12 => (w(OFFSET), w(CURSOR)),
        13 => (c(ivm::Memory::OUTPUT_SIZE), w(CURSOR)),
        14 => (c(ivm::Memory::OUTPUT_SIZE), w(OUTPUT_END)),
        _ => unreachable!("closed bounded region comparisons"),
    }
}
fn addition(out: &mut Vec<F>, row: &[F], slot: usize, left: [F; 4], right: [F; 4], result: [F; 4]) {
    for i in 0..4 {
        let carry = row[CARRIES + slot * 4 + i];
        out.push(bit(carry));
        let old = if i == 0 {
            F::ZERO
        } else {
            row[CARRIES + slot * 4 + i - 1]
        };
        out.push(
            left[i]
                .add(right[i])
                .add(old)
                .sub(result[i])
                .sub(carry.mul(F(1 << 16))),
        );
    }
    out.push(row[CARRIES + slot * 4 + 3]);
}

pub(super) fn append_residues(out: &mut Vec<F>, schedule: Schedule, row: &[F; super::WIDTH]) {
    let start = out.len();
    let selected = row[CARRY + STORE];
    let source = carry_port(row, SOURCE);
    let memory = port(row, 1);
    let initialized = port(row, 2);
    let cursor = port(row, 0);
    for &value in &row[..CARRIES] {
        out.push(bit(value));
        out.push(F::ONE.sub(selected).mul(value));
    }
    for i in 0..4 {
        out.push(limb(row, ADDRESS_WORD, i).sub(row[CARRY + ADDRESS + i]));
    }
    for (i, word) in [STACK_TOP, HEAP_END, CODE_LEN, CURSOR]
        .into_iter()
        .enumerate()
    {
        for j in 0..4 {
            out.push(
                limb(row, word, j).sub(carry_port(row, POLICY + i * packet::WIDTH)[BEFORE + j]),
            );
        }
    }
    let mut less = [F::ZERO; 15];
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
    for (flag, a, b) in [(HEAP, 0, 1), (OUTPUT, 2, 3), (STACK, 4, 5)] {
        out.push(bit(row[flag]));
        out.push(row[flag].sub(selected.mul(F::ONE.sub(less[a])).mul(F::ONE.sub(less[b]))));
    }
    for &v in &row[FLAGS + 3..MEMORY_MASK] {
        out.push(v);
    }
    out.push(selected.sub(row[HEAP]).sub(row[OUTPUT]).sub(row[STACK]));
    out.push(selected.sub(less[6]));
    for i in [7, 8, 9, 10, 11, 13] {
        out.push(less[i]);
    }
    out.push(row[OUTPUT].mul(less[12]));
    out.push(row[OUTPUT].mul(less[14]));
    out.push(source[BEFORE_TAG].mul(selected.sub(row[STACK])));
    for &bit in &word(row, ADDRESS_WORD)[..3] {
        out.push(bit);
    }
    let low = |value: u64| core::array::from_fn(|i| selected.mul(F((value >> (16 * i)) & 0xffff)));
    let limbs = |w| core::array::from_fn(|i| limb(row, w, i));
    addition(out, row, 0, limbs(ADDRESS_WORD), low(8), limbs(END));
    addition(
        out,
        row,
        1,
        core::array::from_fn(|i| {
            row[OUTPUT].mul(F((ivm::Memory::OUTPUT_START >> (16 * i)) & 0xffff))
        }),
        limbs(OFFSET),
        core::array::from_fn(|i| row[OUTPUT].mul(limb(row, ADDRESS_WORD, i))),
    );
    addition(
        out,
        row,
        2,
        limbs(OFFSET),
        [row[OUTPUT].mul(F(8)), F::ZERO, F::ZERO, F::ZERO],
        limbs(OUTPUT_END),
    );
    for w in [OFFSET, OUTPUT_END] {
        for &v in word(row, w) {
            out.push(F::ONE.sub(row[OUTPUT]).mul(v));
        }
    }
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
        35,
        selected,
        selected,
    );
    let half = word(row, ADDRESS_WORD)[3];
    let mut old_mask = F::ZERO;
    let mut new_mask = F::ZERO;
    for byte in 0..16 {
        let old = row[MEMORY_MASK + byte];
        out.push(bit(old));
        out.push(F::ONE.sub(selected).mul(old));
        let chosen = if byte < 8 { selected.sub(half) } else { half };
        let after = old.add(chosen.mul(source[BEFORE_TAG].sub(old)));
        old_mask = old_mask.add(old.mul(F(1 << byte)));
        new_mask = new_mask.add(after.mul(F(1 << byte)));
    }
    out.push(memory[BEFORE_TAG].sub(old_mask));
    out.push(memory[AFTER_TAG].sub(new_mask));
    for i in 0..8 {
        let chosen = if i < 4 { selected.sub(half) } else { half };
        out.push(
            memory[AFTER + i]
                .sub(memory[BEFORE + i])
                .sub(chosen.mul(source[BEFORE + i % 4].sub(memory[BEFORE + i]))),
        );
    }
    let initialize = selected.mul(row[CARRY + INITIALIZE]);
    header(
        out,
        initialized,
        schedule,
        Space::Initialization,
        row[CARRY + ACTIVE],
        cell,
        36,
        initialize,
        initialize,
    );
    let mut previous = F::ZERO;
    let mut updated = F::ZERO;
    for byte in 0..16 {
        let old = row[INITIAL_MASK + byte];
        out.push(bit(old));
        out.push(F::ONE.sub(initialize).mul(old));
        let chosen = if byte < 8 { selected.sub(half) } else { half };
        previous = previous.add(old.mul(F(1 << byte)));
        updated = updated.add(
            initialize
                .mul(old.add(chosen.mul(F::ONE.sub(old))))
                .mul(F(1 << byte)),
        );
    }
    out.push(initialized[BEFORE].sub(previous));
    out.push(initialized[AFTER].sub(updated));
    for offset in [BEFORE, AFTER] {
        for i in 1..8 {
            out.push(initialized[offset + i]);
        }
    }
    out.push(initialized[BEFORE_TAG]);
    out.push(initialized[AFTER_TAG]);
    header(
        out,
        cursor,
        schedule,
        Space::Owner,
        F::ZERO,
        F(23),
        34,
        selected,
        selected,
    );
    for i in 0..4 {
        out.push(cursor[BEFORE + i].sub(limb(row, CURSOR, i)));
        out.push(
            cursor[AFTER + i]
                .sub(limb(row, CURSOR, i))
                .sub(row[OUTPUT].mul(limb(row, OUTPUT_END, i).sub(limb(row, CURSOR, i)))),
        );
    }
    for offset in [BEFORE, AFTER] {
        for i in 4..8 {
            out.push(cursor[offset + i]);
        }
    }
    out.push(cursor[BEFORE_TAG]);
    out.push(cursor[AFTER_TAG]);
    // Original byte log describes writes only, never a synthetic guest read.
    for (i, expected) in [
        pack(&word(row, ADDRESS_WORD)[..32]),
        pack(&word(row, ADDRESS_WORD)[32..]),
        selected.mul(F(8)),
        selected,
    ]
    .into_iter()
    .enumerate()
    {
        out.push(row[LOG + i].sub(expected));
    }
    for i in 0..8 {
        out.push(row[LOG + 4 + i].sub(if i < 4 { source[BEFORE + i] } else { F::ZERO }));
    }
    debug_assert_eq!(out.len() - start, CONSTRAINTS);
}

#[cfg(test)]
pub(super) fn witness(
    address: u64,
    selected: bool,
    policies: [u64; 4],
    old_mask: u16,
    old_init: u16,
    initialize: bool,
    source: u64,
) -> [F; WIDTH] {
    let mut row = [F::ZERO; WIDTH];
    let s = F(u64::from(selected));
    let end = if selected { address.wrapping_add(8) } else { 0 };
    let output = selected
        && address >= ivm::Memory::OUTPUT_START
        && end <= ivm::Memory::OUTPUT_START + ivm::Memory::OUTPUT_SIZE;
    let offset = if output {
        address - ivm::Memory::OUTPUT_START
    } else {
        0
    };
    let values = [
        address,
        end,
        policies[0],
        policies[1],
        policies[2],
        policies[3],
        offset,
        if output { offset + 8 } else { 0 },
    ];
    for (w, value) in values.into_iter().enumerate() {
        for i in 0..64 {
            row[w * 64 + i] = F((value >> i) & 1);
        }
    }
    for i in 0..15 {
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
    for (slot, a, b) in [
        (0, address, if selected { 8 } else { 0 }),
        (
            1,
            if output { ivm::Memory::OUTPUT_START } else { 0 },
            offset,
        ),
        (2, offset, if output { 8 } else { 0 }),
    ] {
        let mut carry = 0;
        for i in 0..4 {
            carry = (((a >> (i * 16)) & 0xffff) + ((b >> (i * 16)) & 0xffff) + carry) >> 16;
            row[CARRIES + slot * 4 + i] = F(carry);
        }
    }
    row[HEAP] = F(u64::from(
        selected && address >= ivm::Memory::HEAP_START && end <= policies[1],
    ));
    row[OUTPUT] = F(u64::from(output));
    row[STACK] = F(u64::from(
        selected && address >= ivm::Memory::STACK_START && end <= policies[0],
    ));
    for i in 0..16 {
        row[MEMORY_MASK + i] = F(u64::from(selected && old_mask & (1 << i) != 0));
        row[INITIAL_MASK + i] = F(u64::from(initialize && old_init & (1 << i) != 0));
    }
    row[LOG] = F(address & 0xffff_ffff);
    row[LOG + 1] = F(address >> 32);
    row[LOG + 2] = s.mul(F(8));
    row[LOG + 3] = s;
    for i in 0..4 {
        row[LOG + 4 + i] = F((source >> (i * 16)) & 0xffff);
    }
    row
}
