//! Original private scalar/branch reads, tags, writes, comparisons and shifts.
//! Total NOT/NEG reuse the ALU; signed MIN/MAX select full original words.
//! Four multiply variants reuse the exact full-width product/correction bank.
//! Successful DIV/DIVU/REM/REMU reuse that product, the remainder comparison and
//! the original shift workspace; their native trap-sensitive operands are public.
//! `DIV_CEIL` adds the exact signed same-sign/nonzero correction in the shared
//! MEAN result workspace, with its own twelve-gas/twelve-cycle original ports.
//! GETGAS reads the original post-debit control word and always writes a public tag.
//! Successful ABS reuses the original subtraction and zero-test cells; its
//! native public-operand and signed-overflow traps remain mandatory.
//! Total ISQRT reuses the full-width product/remainder bank with an exact
//! 32-bit floor root, preserving its source tag and six-gas/six-cycle ports.
//! Signed GCD uses exact normalized products and bounded Bezout in the existing
//! digit workspace, retaining both tags and twelve-gas/twelve-cycle ports.
//! Signed MEAN shares the original 65-bit ADD arithmetic and truncates toward
//! zero, preserving both operand tags and the original two-gas/three-cycle ports.
//!
//! This bank consumes the enclosing dispatcher's private canonical fetch cells
//! and its sole original packet array. It has no independent instruction list,
//! public operand boundary, event digest or production proving adapter.

use super::super::super::{
    alu, branch, immediate_operand, semantic_opcode, shift,
    trace::{bit_count, ceiling, division, mean, multiply, square_root},
    word,
};
use super::*;

mod native_witness;
pub(super) use native_witness::{fill as fill_native_scalar, supported as is_native_public_scalar};
mod gcd;

const SOURCES: usize = 0;
const ALU: usize = SOURCES + word::WIDTH;
pub(super) const COMPARE: usize = ALU + alu::WIDTH;
const PRODUCT_DIGITS: usize = COMPARE + branch::BANK_WIDTH;
const MULTIPLY: usize = PRODUCT_DIGITS + 64;
pub(super) const COUNT: usize = MULTIPLY + multiply::WIDTH;
pub(super) const MOVE: usize = COUNT + bit_count::WIDTH;
const MOVE_ZERO: usize = MOVE;
const MOVE_INVERSE: usize = MOVE + 1;
const MEAN: usize = MOVE + 2;
pub(super) const SHIFT: usize = MEAN + mean::WIDTH;
pub(super) const WIDTH: usize = SHIFT + shift::BANK_WIDTH;

/// Native successful conditional moves read the condition first, then the
/// optional source and destination only when the full condition is nonzero.
pub(super) fn is_conditional_move(instruction: u32) -> bool {
    matches!(
        wide::opcode(instruction),
        wide::arithmetic::CMOV | wide::arithmetic::CMOVI
    )
}

pub(super) fn is_bit_count(instruction: u32) -> bool {
    matches!(
        wide::opcode(instruction),
        wide::arithmetic::POPCNT | wide::arithmetic::CLZ | wide::arithmetic::CTZ
    )
}

fn division_kind(instruction: u32) -> Option<usize> {
    match wide::opcode(instruction) {
        wide::arithmetic::DIV => Some(0),
        wide::arithmetic::DIVU => Some(1),
        wide::arithmetic::REM => Some(2),
        wide::arithmetic::REMU => Some(3),
        wide::arithmetic::DIV_CEIL => Some(4),
        _ => None,
    }
}

/// Successful division still requires both native trap-sensitive operands public.
/// TODO: Compose original failed-attempt ports before admitting private traps.
pub(super) fn is_division(instruction: u32) -> bool {
    division_kind(instruction).is_some()
}

pub(super) fn is_division_ceiling(instruction: u32) -> bool {
    wide::opcode(instruction) == wide::arithmetic::DIV_CEIL
}

fn multiply_kind(instruction: u32) -> Option<usize> {
    match wide::opcode(instruction) {
        wide::arithmetic::MUL => Some(0),
        wide::arithmetic::MULHU => Some(1),
        wide::arithmetic::MULHSU => Some(2),
        wide::arithmetic::MULH => Some(3),
        _ => None,
    }
}

pub(super) fn is_multiply(instruction: u32) -> bool {
    multiply_kind(instruction).is_some()
}

fn shift_kind(instruction: u32) -> Option<usize> {
    match wide::opcode(instruction) {
        wide::arithmetic::SLL => Some(0),
        wide::arithmetic::SRL => Some(1),
        wide::arithmetic::SRA => Some(2),
        wide::arithmetic::ROTL | wide::arithmetic::ROTL_IMM => Some(3),
        wide::arithmetic::ROTR | wide::arithmetic::ROTR_IMM => Some(4),
        _ => None,
    }
}

pub(super) fn is_rotate(instruction: u32) -> bool {
    matches!(shift_kind(instruction), Some(3 | 4))
}

fn is_getgas(instruction: u32) -> bool {
    wide::opcode(instruction) == wide::system::GETGAS
}

pub(super) fn is_square_root(instruction: u32) -> bool {
    wide::opcode(instruction) == wide::arithmetic::ISQRT
}

pub(super) fn is_mean(instruction: u32) -> bool {
    wide::opcode(instruction) == wide::arithmetic::MEAN
}

fn is_absolute(instruction: u32) -> bool {
    wide::opcode(instruction) == wide::arithmetic::ABS
}

fn reads_left(instruction: u32) -> bool {
    !is_getgas(instruction)
}

fn right_immediate(instruction: u32) -> Option<u64> {
    match wide::opcode(instruction) {
        // GETGAS has no register sources. Its result is linked directly to the
        // original gas-debit port; unused arithmetic workspaces stay canonical.
        wide::system::GETGAS => return Some(0),
        // Unary instructions never read the encoded rs2 byte. NEG routes the
        // original rs1 packet into the right arithmetic operand separately.
        wide::arithmetic::NEG
        | wide::arithmetic::ABS
        | wide::arithmetic::POPCNT
        | wide::arithmetic::CLZ
        | wide::arithmetic::CTZ
        | wide::arithmetic::ISQRT => return Some(0),
        wide::arithmetic::NOT => return Some(u64::MAX),
        wide::arithmetic::CMOVI => {
            return Some(i64::cast_unsigned(i64::from(wide::imm8(instruction))));
        }
        _ => {}
    }
    if matches!(
        wide::opcode(instruction),
        wide::arithmetic::ROTL_IMM | wide::arithmetic::ROTR_IMM
    ) {
        Some(u64::from(i8::cast_unsigned(wide::imm8(instruction))))
    } else {
        immediate_operand(instruction)
    }
}

fn alu_opcode(instruction: u32) -> u8 {
    match wide::opcode(instruction) {
        wide::arithmetic::NEG | wide::arithmetic::ABS => wide::arithmetic::SUB,
        wide::arithmetic::NOT => wide::arithmetic::XOR,
        opcode => semantic_opcode(opcode),
    }
}

fn is_alu(instruction: u32) -> bool {
    !is_absolute(instruction)
        && matches!(
            alu_opcode(instruction),
            wide::arithmetic::ADD
                | wide::arithmetic::SUB
                | wide::arithmetic::AND
                | wide::arithmetic::OR
                | wide::arithmetic::XOR
        )
}

/// The predicate is selected only from the canonical artifact fetch, never a
/// caller predicate or a scalar word reduced modulo the proof field.
fn comparison_predicate(instruction: u32) -> Option<usize> {
    match wide::opcode(instruction) {
        wide::control::BEQ => Some(0),
        wide::control::BNE => Some(1),
        wide::control::BLT => Some(2),
        wide::control::BGE => Some(3),
        wide::control::BLTU => Some(4),
        wide::control::BGEU => Some(5),
        wide::arithmetic::SLT | wide::arithmetic::MIN | wide::arithmetic::MAX => Some(2),
        wide::arithmetic::SLTU => Some(4),
        wide::arithmetic::SEQ => Some(0),
        wide::arithmetic::SNE => Some(1),
        _ => None,
    }
}

pub(super) fn is_branch(instruction: u32) -> bool {
    matches!(
        wide::opcode(instruction),
        wide::control::BEQ
            | wide::control::BNE
            | wide::control::BLT
            | wide::control::BGE
            | wide::control::BLTU
            | wide::control::BGEU
    )
}

fn left_register(instruction: u32) -> usize {
    if wide::opcode(instruction) == wide::arithmetic::CMOV {
        wide::rs2(instruction)
    } else if is_branch(instruction) {
        wide::rd(instruction)
    } else {
        wide::rs1(instruction)
    }
}

fn right_register(instruction: u32) -> usize {
    if is_branch(instruction) || wide::opcode(instruction) == wide::arithmetic::CMOV {
        wide::rs1(instruction)
    } else {
        wide::rs2(instruction)
    }
}

fn has_destination(instruction: u32) -> bool {
    !is_branch(instruction) && wide::rd(instruction) != 0
}

/// The same private comparison result controls the original PC producer.
pub(super) fn branch_taken(row: &[F; super::WIDTH]) -> F {
    row[SCALAR + COMPARE + branch::TAKEN_BANK_OFFSET]
}

pub(super) fn is_gcd(instruction: u32) -> bool {
    wide::opcode(instruction) == wide::arithmetic::GCD
}

pub(super) fn is_supported(instruction: u32) -> bool {
    is_getgas(instruction)
        || is_gcd(instruction)
        || is_square_root(instruction)
        || is_mean(instruction)
        || is_absolute(instruction)
        || is_alu(instruction)
        || comparison_predicate(instruction).is_some()
        || shift_kind(instruction).is_some()
        || is_multiply(instruction)
        || is_bit_count(instruction)
        || is_conditional_move(instruction)
        || is_division(instruction)
}

pub(super) fn append_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    program: &Program,
    schedule: Schedule,
    row: &[F; super::WIDTH],
    packets: &OriginalPackets,
) {
    let weighted = |value: &dyn Fn(u32) -> F| {
        program
            .words
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (i, w)| {
                if is_supported(w) {
                    sum.add(row[FETCH + i].mul(value(w)))
                } else {
                    sum
                }
            })
    };
    let select = |predicate: &dyn Fn(u32) -> bool| weighted(&|w| F(u64::from(predicate(w))));
    // LOAD and LDI use this same original atomic destination port. Their
    // values are owned by the memory effect relation and admitted literal table,
    // respectively; no sequential diagnostic tag event is fabricated.
    let external = |value: &dyn Fn(u32) -> F| {
        program
            .words
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (i, word)| {
                sum.add(row[FETCH + i].mul(value(word)))
            })
    };
    let load = external(&|word| F(u64::from(role(word) == Some(Role::Load))));
    let external_destination = external(&|word| {
        F(u64::from(
            matches!(role(word), Some(Role::Load | Role::Literal)) && wide::rd(word) != 0,
        ))
    });
    let external_index = external(&|word| {
        if matches!(role(word), Some(Role::Load | Role::Literal)) {
            F(wide::rd(word) as u64)
        } else {
            F::ZERO
        }
    });
    let register_left = select(&|w| reads_left(w));
    let division_selected = select(&|w| is_division(w));
    let ceiling_selected = select(&|w| is_division_ceiling(w));
    let absolute_selected = select(&|w| is_absolute(w));
    let mean_selected = select(&|w| is_mean(w));
    let square_selected = select(&|w| is_square_root(w));
    let gcd_selected = select(&|w| is_gcd(w));
    let division_signed = select(&|w| division_kind(w).is_some_and(division::signed_kind));
    let move_selected = select(&|w| is_conditional_move(w));
    let register_move = select(&|w| wide::opcode(w) == wide::arithmetic::CMOV);
    let move_taken = F::ONE.sub(row[SCALAR + MOVE_ZERO]);
    let register_right =
        select(&|w| right_immediate(w).is_none()).sub(register_move.mul(F::ONE.sub(move_taken)));
    let move_destination =
        select(&|w| is_conditional_move(w) && has_destination(w)).mul(move_taken);
    let ordinary_destination = select(&|w| !is_conditional_move(w) && has_destination(w));
    let destination = ordinary_destination
        .add(move_destination)
        .add(external_destination);
    for (slot, index, enabled, write) in [
        (
            SCALAR_LEFT,
            weighted(&|w| {
                if reads_left(w) {
                    F(left_register(w) as u64)
                } else {
                    F::ZERO
                }
            }),
            register_left,
            F::ZERO,
        ),
        (
            SCALAR_RIGHT,
            weighted(&|w| {
                if right_immediate(w).is_none() {
                    F(right_register(w) as u64).mul(if is_conditional_move(w) {
                        move_taken
                    } else {
                        F::ONE
                    })
                } else {
                    F::ZERO
                }
            }),
            register_right,
            F::ZERO,
        ),
        (
            SCALAR_DESTINATION,
            weighted(&|w| {
                if has_destination(w) {
                    F(wide::rd(w) as u64).mul(if is_conditional_move(w) {
                        move_taken
                    } else {
                        F::ONE
                    })
                } else {
                    F::ZERO
                }
            })
            .add(external_index),
            destination,
            destination,
        ),
    ] {
        header(
            out,
            schedule,
            packets,
            slot,
            Space::Register,
            index,
            F::ZERO,
            enabled,
            write,
        );
    }
    let p = &packets.fields;
    let source = word::Sources::new(&row[SCALAR + SOURCES..SCALAR + ALU]);
    source.append_residues(out);
    let negating = select(&|w| wide::opcode(w) == wide::arithmetic::NEG).add(absolute_selected);
    for limb in 0..4 {
        // Architectural rs1 remains the original left read for tags, aliases
        // and private history; only the shared ALU operands become (0, rs1).
        let left = p[SCALAR_LEFT][BEFORE + limb];
        out.push(source.limb(0, limb).sub(F::ONE.sub(negating).mul(left)));
        let immediate =
            weighted(&|w| right_immediate(w).map_or(F::ZERO, |v| constant_limb(v, limb)));
        out.push(
            source
                .limb(1, limb)
                .sub(p[SCALAR_RIGHT][BEFORE + limb])
                .sub(immediate)
                .sub(negating.mul(left)),
        );
    }
    // A ZK binary register instruction rejects differently tagged operands,
    // even when its destination is r0. Constants and unary operations inherit rs1's tag.
    out.push(
        register_right
            .sub(register_move.mul(move_taken))
            .mul(p[SCALAR_LEFT][BEFORE_TAG].sub(p[SCALAR_RIGHT][BEFORE_TAG])),
    );
    // CMOV may copy a secret-tagged value, but its condition must be public,
    // including a false condition or rd0. CMOVI writes a public immediate.
    out.push(move_selected.mul(p[SCALAR_LEFT][BEFORE_TAG]));
    // Conditional branches are forbidden on either private-tagged operand,
    // including equal tags and r0 aliases; their execution path stays private
    // in this relation without changing native tag policy.
    let branching = select(&|w| is_branch(w));
    out.push(branching.mul(p[SCALAR_LEFT][BEFORE_TAG]));
    out.push(branching.mul(p[SCALAR_RIGHT][BEFORE_TAG]));
    // Native division may trap on its values; public tags are mandatory even
    // for rd0 and even when the two private tags would otherwise match.
    out.push(division_selected.mul(p[SCALAR_LEFT][BEFORE_TAG]));
    out.push(division_selected.mul(p[SCALAR_RIGHT][BEFORE_TAG]));
    // ABS can trap on i64::MIN, so even a discarded rd0 requires a public input.
    out.push(absolute_selected.mul(p[SCALAR_LEFT][BEFORE_TAG]));
    for (slot, zero) in [
        (SCALAR_LEFT, select(&|w| left_register(w) == 0)),
        (
            SCALAR_RIGHT,
            select(&|w| right_immediate(w).is_none() && right_register(w) == 0),
        ),
    ] {
        for field in (BEFORE..BEFORE + 4).chain([BEFORE_TAG]) {
            out.push(zero.mul(p[slot][field]));
        }
    }
    // These are pre-read aliases, not reads of the just-written destination.
    // The full private history additionally binds all surrounding instructions.
    for (left, right, equal) in [
        (
            SCALAR_LEFT,
            SCALAR_RIGHT,
            select(&|w| right_immediate(w).is_none() && left_register(w) == right_register(w)),
        ),
        (
            SCALAR_LEFT,
            SCALAR_DESTINATION,
            select(&|w| has_destination(w) && wide::rd(w) == left_register(w)),
        ),
        (
            SCALAR_RIGHT,
            SCALAR_DESTINATION,
            select(&|w| {
                right_immediate(w).is_none()
                    && has_destination(w)
                    && wide::rd(w) == right_register(w)
            }),
        ),
    ] {
        for field in (BEFORE..BEFORE + 4).chain([BEFORE_TAG]) {
            // Conditional reads/writes do not exist on the untaken path.
            // Original packet enable cells keep this alias check at degree4.
            out.push(
                equal
                    .mul(p[left][ENABLED])
                    .mul(p[right][ENABLED])
                    .mul(p[left][field].sub(p[right][field])),
            );
        }
    }
    let bank = &row[SCALAR + ALU..SCALAR + COMPARE];
    let selectors = [
        wide::arithmetic::SUB,
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
    ]
    .map(|opcode| select(&|w| alu_opcode(w) == opcode));
    // All banks stay fully constrained on the same original private source
    // bits, even when their result is unused. Outside GCD the ALU defaults to ADD, while
    // comparison selectors all zero force TAKEN=0 but retain exact subtraction,
    // zero/inverse and equality witnesses. Quartic checks are never gated.
    // No bank allocates an intermediate private residual vector.
    alu::append_residues(out, bank, source, selectors, F::ONE.sub(gcd_selected));
    // MEAN uses the same canonical ADD limbs/carry, never a reduced full word.
    // The separate result bank is range-constrained without gating the quartics.
    let mean_result = &row[SCALAR + MEAN..SCALAR + SHIFT];
    out.extend(mean_result[4..36].iter().copied().map(word::radix4));
    // Carries and flags remain Boolean in both roles. Cell41 is a field
    // inverse only on DIV_CEIL; on MEAN it remains the original low-sum bit.
    out.extend(mean_result[36..ceiling::INVERSE].iter().copied().map(bit));
    out.push(
        F::ONE
            .sub(ceiling_selected)
            .mul(bit(mean_result[ceiling::INVERSE])),
    );
    out.extend(mean_result[ceiling::INVERSE + 1..].iter().copied().map(bit));
    for limb in 0..4 {
        out.push(mean_result[limb].sub(word::pack(&mean_result[4 + 8 * limb..12 + 8 * limb], 2)));
    }
    mean::append_arithmetic_residues(out, mean_result, bank, source, mean_selected);
    out.extend(mean_result.iter().map(|cell| {
        F::ONE
            .sub(mean_selected)
            .sub(ceiling_selected)
            .sub(gcd_selected)
            .mul(*cell)
    }));
    let comparison = &row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS];
    let product = &row[SCALAR + MULTIPLY..SCALAR + COUNT];
    let shifts = &row[SCALAR + SHIFT..super::WIDTH];
    branch::append_bank_residues(
        out,
        comparison,
        core::array::from_fn(|operand| {
            core::array::from_fn(|limb| {
                let divided = if operand == 0 {
                    shifts[division::REMAINDER + limb]
                } else {
                    product[multiply::SIGNED_SIGNED + limb]
                };
                F::ONE
                    .sub(division_selected)
                    .mul(source.limb(operand, limb))
                    .add(division_selected.mul(divided))
            })
        }),
        [source.sign(0), source.sign(1)],
        core::array::from_fn(|predicate| select(&|w| comparison_predicate(w) == Some(predicate))),
    );
    // Like the ALU and shift banks, the exact product stays constrained on
    // every row outside the explicitly disjoint division/square/GCD owners.
    // Keeping range equations unconditional preserves degree four;
    // only destination selection depends on the private canonical fetch.
    multiply::append_residues(
        out,
        product,
        &row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY],
        source,
        multiply::Selection {
            multiply: F::ONE
                .sub(division_selected)
                .sub(square_selected)
                .sub(gcd_selected),
            division: division_selected,
            square: square_selected,
            other: gcd_selected,
            signed: division_signed,
            success: division_selected.add(square_selected),
            quotient: core::array::from_fn(|limb| shifts[division::QUOTIENT + limb]),
        },
    );
    let product_destinations = core::array::from_fn::<_, 4, _>(|kind| {
        select(&|w| multiply_kind(w) == Some(kind) && has_destination(w))
    });
    // The original canonical bits uniquely determine every prefix, including
    // unrelated instructions and padding, except the selected GCD digit owner.
    // Only CLZ reverses this public-code
    // selected traversal; no secret value controls a branch in these equations.
    let count_prefixes = &row[SCALAR + COUNT..SCALAR + MOVE];
    bit_count::append_residues(
        &mut crate::execution_proofs::ivm_step_air::residues::Scaled::new(
            out,
            F::ONE.sub(gcd_selected),
        ),
        count_prefixes,
        source.bits(0),
        select(&|w| wide::opcode(w) == wide::arithmetic::CLZ),
    );
    let prefix_count = count_prefixes.iter().copied().fold(F::ZERO, F::add);
    let population = source.bits(0).iter().copied().fold(F::ZERO, F::add);
    // Canonical bit sums cannot wrap the field. On ABS rows the routed right
    // operand is the original source and this delta is zero exactly at i64::MIN.
    // Reusing the zero-test owner adds no cells; the selected delta is quadratic,
    // so its inverse/flag equations stay at most cubic. Other rows, including
    // CMOV and padding, retain the original population zero test. GCD selects
    // the original right population for its total zero-denominator branch.
    let minimum_delta = F::ONE
        .sub(source.sign(1))
        .add(source.bits(1)[..63].iter().copied().fold(F::ZERO, F::add));
    let right_population = source.bits(1).iter().copied().fold(F::ZERO, F::add);
    let zero_delta = population
        .add(absolute_selected.mul(minimum_delta.sub(population)))
        .add(gcd_selected.mul(right_population.sub(population)));
    let zero = row[SCALAR + MOVE_ZERO];
    let inverse = row[SCALAR + MOVE_INVERSE];
    out.push(bit(zero));
    out.push(zero_delta.mul(zero));
    out.push(zero_delta.mul(inverse).sub(F::ONE.sub(zero)));
    out.push(zero.mul(inverse));
    // TODO: Compose original failed-attempt ports before representing ABS traps.
    // This successful-step component must reject overflow, including rd0.
    out.push(absolute_selected.mul(zero));
    let population_destination =
        select(&|w| wide::opcode(w) == wide::arithmetic::POPCNT && has_destination(w));
    let prefix_destination = select(&|w| {
        matches!(
            wide::opcode(w),
            wide::arithmetic::CLZ | wide::arithmetic::CTZ
        ) && has_destination(w)
    });
    let mut kinds = core::array::from_fn(|kind| select(&|w| shift_kind(w) == Some(kind)));
    // Canonical SLL on every non-shift row, including zero-source padding.
    kinds[0] = kinds[0].add(F::ONE.sub(select(&|w| shift_kind(w).is_some())));
    // Reuse the original 208 cells; barrel equations are at most cubic.
    // Division's radix-four checks remain unconditional and degree four.
    shift::append_bank_residues(
        &mut crate::execution_proofs::ivm_step_air::residues::Scaled::new(
            out,
            F::ONE
                .sub(division_selected)
                .sub(square_selected)
                .sub(gcd_selected),
        ),
        shifts,
        source,
        kinds,
    );
    let gas_digits = core::array::from_fn::<_, 32, _>(|digit| {
        let offset = WORDS + 64 + 2 * digit;
        row[offset].add(F(2).mul(row[offset + 1]))
    });
    division::append_residues(
        out,
        shifts,
        product,
        source,
        &gas_digits,
        comparison[branch::BORROW + 3],
        division::Selection {
            active: division_selected,
            signed: division_signed,
            ceiling: ceiling_selected,
            out_of_gas: F::ZERO,
            assertion_failed: F::ZERO,
        },
    );
    // Original source and pre-debit gas digits own the exact floor equation.
    // This successful-only dispatcher separately refuses gas underflow; no
    // trap selector may suppress the root or its original destination.
    square_root::append_residues(
        out,
        shifts,
        product,
        source,
        &gas_digits,
        square_selected,
        F::ZERO,
        F::ZERO,
    );
    let square_destination = select(&|w| is_square_root(w) && has_destination(w));
    gcd::append_residues(out, &row[SCALAR..], source, gcd_selected, zero);
    let gcd_destination = select(&|w| is_gcd(w) && has_destination(w));
    ceiling::append_residues(out, mean_result, shifts, ceiling_selected);
    let ceiling_destination = select(&|w| is_division_ceiling(w) && has_destination(w));
    let shift_destination = select(&|w| shift_kind(w).is_some() && has_destination(w));
    let alu_destination = select(&|w| is_alu(w) && wide::rd(w) != 0);
    let gas_destination = select(&|w| is_getgas(w) && has_destination(w));
    let absolute_destination = select(&|w| is_absolute(w) && has_destination(w));
    let mean_destination = select(&|w| is_mean(w) && has_destination(w));
    let minimum_destination =
        select(&|w| wide::opcode(w) == wide::arithmetic::MIN && has_destination(w));
    let maximum_destination =
        select(&|w| wide::opcode(w) == wide::arithmetic::MAX && has_destination(w));
    let comparison_destination = select(&|w| {
        comparison_predicate(w).is_some()
            && !matches!(
                wide::opcode(w),
                wide::arithmetic::MIN | wide::arithmetic::MAX
            )
            && has_destination(w)
    });
    let division_destinations = core::array::from_fn::<_, 4, _>(|kind| {
        select(&|w| division_kind(w) == Some(kind) && has_destination(w))
    });
    let taken = comparison[branch::TAKEN_BANK_OFFSET];
    for limb in 0..4 {
        let boolean = if limb == 0 {
            comparison[branch::TAKEN_BANK_OFFSET]
        } else {
            F::ZERO
        };
        // The predicate and operands are canonical bank cells. Multiplying
        // this quadratic full-word selection by fetch keeps degree three.
        let left = source.limb(0, limb);
        let right = source.limb(1, limb);
        let minimum = taken.mul(left).add(F::ONE.sub(taken).mul(right));
        let maximum = taken.mul(right).add(F::ONE.sub(taken).mul(left));
        let multiplied = [
            multiply::PRODUCT,
            multiply::PRODUCT + 4,
            multiply::SIGNED_UNSIGNED,
            multiply::SIGNED_SIGNED,
        ]
        .into_iter()
        .zip(product_destinations)
        .fold(F::ZERO, |sum, (offset, selected)| {
            sum.add(selected.mul(product[offset + limb]))
        });
        out.push(
            p[SCALAR_DESTINATION][AFTER + limb]
                .mul(F::ONE.sub(load))
                .sub(external(&|word| {
                    if role(word) == Some(Role::Literal) && wide::rd(word) != 0 {
                        constant_limb(
                            program
                                .contract
                                .scalar_literal(wide::literal_index(word) as u16)
                                .expect("Program retains admitted scalar literal"),
                            limb,
                        )
                    } else {
                        F::ZERO
                    }
                }))
                // The same original port is range-constrained and debited by
                // the dispatcher, and retained in its mandatory history join.
                // Do not accept a second supplied gas value or the pre-debit word.
                .sub(gas_destination.mul(p[GAS_DEBIT][AFTER + limb]))
                .sub(multiplied)
                .sub(square_destination.mul(shifts[division::QUOTIENT + limb]))
                .sub(gcd_destination.mul(gcd::limb(&row[SCALAR..], gcd::RESULT, limb)))
                .sub(division_destinations.iter().enumerate().fold(
                    F::ZERO,
                    |sum, (kind, selected)| {
                        let result = if kind < 2 {
                            division::QUOTIENT_RESULT
                        } else {
                            division::REMAINDER_RESULT
                        };
                        sum.add(selected.mul(shifts[result + limb]))
                    },
                ))
                .sub(move_destination.mul(source.limb(1, limb)))
                .sub(if limb == 0 {
                    population_destination
                        .mul(population)
                        .add(prefix_destination.mul(prefix_count))
                } else {
                    F::ZERO
                })
                .sub(
                    absolute_destination.mul(
                        source
                            .sign(1)
                            .mul(bank[alu::RESULT + limb])
                            .add(F::ONE.sub(source.sign(1)).mul(right)),
                    ),
                )
                .sub(
                    mean_destination
                        .add(ceiling_destination)
                        .mul(mean_result[limb]),
                )
                .sub(alu_destination.mul(bank[alu::RESULT + limb]))
                .sub(comparison_destination.mul(boolean))
                .sub(minimum_destination.mul(minimum))
                .sub(maximum_destination.mul(maximum))
                .sub(shift_destination.mul(shifts[shift::RESULT + limb])),
        );
    }
    let moved_tag = select(&|w| wide::opcode(w) == wide::arithmetic::CMOV && has_destination(w))
        .mul(move_taken)
        .mul(p[SCALAR_RIGHT][BEFORE_TAG]);
    // GETGAS has a disabled (zero) left packet, so its output tag is public
    // regardless of the overwritten register's old tag or unused encoding bytes.
    out.push(
        p[SCALAR_DESTINATION][AFTER_TAG]
            .mul(F::ONE.sub(load))
            .sub(ordinary_destination.mul(p[SCALAR_LEFT][BEFORE_TAG]))
            .sub(moved_tag),
    );
}

#[cfg(test)]
mod tests;
