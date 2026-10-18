//! Bounded workspace construction from original native ports, never new events.
//!
//! These assignments are untrusted witness generation. Polynomial equations,
//! not these computations, establish fetch/control and instruction semantics.
//! The native join admits public arithmetic and bit operations, LDI64, public-root
//! LOAD64/STORE64 and root JALR.
//! TODO: join private/wide memory, other instructions and complete native faults
//! before extending this coverage. No second value/tag event is manufactured.

use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(in super::super) enum Error {
    Unsupported,
    Shape,
}

fn supported(instruction: u32) -> bool {
    scalar::is_native_public_scalar(instruction)
        || matches!(
            wide::opcode(instruction),
            wide::memory::STORE64 | wide::memory::LOAD64 | wide::memory::LDI64
        )
        || role(instruction) == Some(Role::Return)
}

/// Restrict the shared dispatcher to this native source's actual instruction
/// coverage. The original public words select fixed coefficients; neither a
/// constructor refusal nor a supplied role is a premise of these equations.
pub(in super::super) fn append_subset_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    program: &Program,
    row: &[F; WIDTH],
    packets: &OriginalPackets,
) {
    let mut returning = F::ZERO;
    let mut public_scalar = F::ZERO;
    for (slot, fetch) in program.fetch(row).iter().copied().enumerate() {
        let instruction = program.words.get(slot).copied();
        out.push(fetch.mul(F(u64::from(!instruction.is_some_and(supported)))));
        if instruction.is_some_and(|instruction| role(instruction) == Some(Role::Return)) {
            returning = returning.add(fetch);
        }
        if instruction.is_some_and(scalar::is_native_public_scalar) {
            public_scalar = public_scalar.add(fetch);
        }
    }
    // The sole root has no parent. The shared relation derives its exact
    // protected sentinel, depth and halt once this original parent is zero.
    for limb in 0..4 {
        out.push(returning.mul(packets.fields[RETURN_PARENT][BEFORE + limb]));
    }
    // Ordinary interpreter tag rules are unchanged. This component admits only
    // public operands; equal private tags accepted by broader scalar diagnostic
    // equations cannot widen the native invocation's declared coverage.
    for port in [SCALAR_LEFT, SCALAR_RIGHT] {
        out.push(public_scalar.mul(packets.fields[port][BEFORE_TAG]));
    }
}

fn bits(target: &mut [F], value: u64) {
    for (index, field) in target.iter_mut().enumerate() {
        *field = F((value >> index) & 1);
    }
}
fn carries(target: &mut [F], left: u64, right: u64, subtract: bool) {
    let mut carry = 0;
    for (limb, field) in target.iter_mut().enumerate() {
        let a = (left >> (16 * limb)) & 0xffff;
        let b = (right >> (16 * limb)) & 0xffff;
        carry = if subtract {
            u64::from(a < b + carry)
        } else {
            (a + b + carry) >> 16
        };
        *field = F(carry);
    }
}

/// Fill an already funded row. Every value comes from original ports or public
/// code; no terminal recomputation is admitted as an execution truth field.
pub(in super::super) fn fill(
    row: &mut [F; WIDTH],
    program: &Program,
    packets: &OriginalPackets,
) -> Result<(), Error> {
    row.fill(F::ZERO);
    let ports = &packets.fields;
    if ports[PC_READ][ENABLED] == F::ZERO {
        // Native inactive windows contain no accesses at all. The dispatcher
        // must constrain this complete-zero shape, not invent a running write.
        if ports.iter().flatten().any(|field| *field != F::ZERO) {
            return Err(Error::Shape);
        }
        scalar::fill_native_scalar(row, None, 0, 0);
        return Ok(());
    }
    let word = |port: usize, offset: usize| packet::half(&ports[port], offset, 0);
    let pc = word(PC_READ, BEFORE);
    let relative = pc
        .checked_sub(u64::from(program.first_pc))
        .ok_or(Error::Shape)?;
    if !relative.is_multiple_of(4) {
        return Err(Error::Shape);
    }
    let slot = usize::try_from(relative / 4).map_err(|_| Error::Shape)?;
    let instruction = *program.words.get(slot).ok_or(Error::Shape)?;
    let returning = role(instruction) == Some(Role::Return);
    let memory = matches!(
        wide::opcode(instruction),
        wide::memory::STORE64 | wide::memory::LOAD64
    );
    let public_scalar = scalar::is_native_public_scalar(instruction);
    if !supported(instruction) {
        return Err(Error::Unsupported);
    }
    // This source has one root only. Child/host execution and non-root return
    // witness production stay closed even though the shared AIR has more roles.
    if returning && word(RETURN_PARENT, BEFORE) != 0 {
        return Err(Error::Unsupported);
    }
    let cost = ivm::gas::cost_of(instruction).ok_or(Error::Unsupported)?;
    let gas = word(GAS_DEBIT, BEFORE);
    let cycles = word(CYCLE_WRITE, BEFORE);
    let base = if memory { word(MEMORY_BASE, BEFORE) } else { 0 };
    let immediate = if memory {
        i64::cast_unsigned(i64::from(wide::imm8(instruction)))
    } else {
        0
    };
    let target = if returning { word(PC_WRITE, AFTER) } else { 0 };
    let raw_return = if returning {
        word(RETURN_REGISTER, BEFORE)
    } else {
        0
    };
    let delta = raw_return
        .checked_sub(target)
        .filter(|delta| *delta < 4)
        .ok_or(Error::Shape)?;
    let remaining_cycles = program
        .cycle_limit
        .checked_sub(1)
        .and_then(|maximum| maximum.checked_sub(cycles))
        .ok_or(Error::Shape)?;
    row[FETCH + slot] = F::ONE;
    for (index, value) in [
        pc,
        gas,
        word(GAS_DEBIT, AFTER),
        cycles,
        word(CYCLE_WRITE, AFTER),
        target,
        base,
        base.wrapping_add(immediate),
        raw_return,
        remaining_cycles,
    ]
    .into_iter()
    .enumerate()
    {
        bits(
            &mut row[WORDS + index * 64..WORDS + (index + 1) * 64],
            value,
        );
    }
    carries(&mut row[CARRIES..CARRIES + 4], gas, cost, true);
    carries(&mut row[CARRIES + 4..CARRIES + 8], cycles, 1, false);
    carries(&mut row[CARRIES + 8..CARRIES + 12], base, immediate, false);
    carries(&mut row[CARRIES + 12..CARRIES + 16], target, delta, false);
    carries(
        &mut row[CARRIES + 16..CARRIES + 20],
        program.cycle_limit - 1,
        cycles,
        true,
    );
    bits(&mut row[RETURN_DELTA..SCALAR], delta);
    for (side, offset) in [BEFORE, AFTER].into_iter().enumerate() {
        bits(
            &mut row[DEPTH_BITS + side * DEPTH_BITS_PER_VALUE
                ..DEPTH_BITS + (side + 1) * DEPTH_BITS_PER_VALUE],
            word(CALL_DEPTH, offset),
        );
    }
    if returning {
        row[RETURN_INVERSE] = F(word(RETURN_ACTIVE, BEFORE)).inv().unwrap_or(F::ZERO);
        row[HALT] = F(u64::from(target == program.code_end()));
        row[HALT_INVERSE] = F(target)
            .sub(F(program.code_end()))
            .inv()
            .unwrap_or(F::ZERO);
    }
    let left = word(SCALAR_LEFT, BEFORE);
    let right = word(SCALAR_RIGHT, BEFORE);
    scalar::fill_native_scalar(row, public_scalar.then_some(instruction), left, right);
    Ok(())
}

#[cfg(test)]
mod tests;
