//! Scan workspace arithmetic derived from original producer fields.
//!
//! These assignments are witness generation. The existing operand/scan equations
//! establish the result, never this native computation or an observed commitment.

use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(in super::super) enum Error {
    Shape,
}

fn bits(target: &mut [F], value: u64) {
    for (index, field) in target.iter_mut().enumerate() {
        *field = F((value >> index) & 1);
    }
}

/// Fill one already funded row from unchanged original packet fields. No ports,
/// tags, clocks or private initialization masks are synthesized by this function.
pub(in super::super) fn fill(
    row: &mut [F; WIDTH],
    offset: usize,
    ports: Ports<'_>,
) -> Result<(), Error> {
    if offset >= CELLS {
        return Err(Error::Shape);
    }
    let selected = ports.active[ENABLED] == F::ONE;
    if !selected && ports.active[ENABLED] != F::ZERO {
        return Err(Error::Shape);
    }
    let start = packet::half(ports.result_start, BEFORE, 0);
    let end = packet::half(ports.result_end, BEFORE, 0);
    let active = packet::half(ports.active, BEFORE, 0);
    let parent = packet::half(ports.parent, BEFORE, 0);
    let length = end.checked_sub(start).ok_or(Error::Shape)?;
    if start >= 1 << 36
        || end >= 1 << 36
        || !start.is_multiple_of(8)
        || !end.is_multiple_of(8)
        || length > 1 << 16
        || (selected && length == 0)
        || active > u64::from(u16::MAX)
        || parent > u64::from(u16::MAX)
    {
        return Err(Error::Shape);
    }
    let cell = (start >> 4) + offset as u64;
    let child_mask = packet::half(ports.child, BEFORE, 0);
    let parent_mask = packet::half(ports.copyback, BEFORE, 0);
    if child_mask > u64::from(u16::MAX) || parent_mask > u64::from(u16::MAX) {
        return Err(Error::Shape);
    }
    row.fill(F::ZERO);
    bits(&mut row[START..END], start);
    bits(&mut row[END..CELL], end);
    bits(&mut row[CELL..COMPARE], cell);
    bits(&mut row[ACTIVE..PARENT], active);
    bits(&mut row[PARENT..LENGTH], parent);
    bits(&mut row[LENGTH..LENGTH_INVERSE], length);
    row[LENGTH_INVERSE] = F(length).inv().unwrap_or(F::ZERO);
    row[ACTIVE_INVERSE] = F(active).inv().unwrap_or(F::ZERO);
    row[HAS_PARENT] = F(u64::from(parent != 0));
    row[PARENT_INVERSE] = F(parent).inv().unwrap_or(F::ZERO);
    bits(&mut row[CHILD_MASK..PARENT_MASK], child_mask);
    bits(&mut row[PARENT_MASK..LOWER], parent_mask);
    let lower = selected && cell * 16 >= start && cell * 16 < end;
    let upper = selected && cell * 16 + 8 < end;
    row[LOWER] = F(u64::from(lower));
    row[UPPER] = F(u64::from(upper));
    row[CHILD_ENABLED] = F(u64::from(lower || upper));
    row[PARENT_ENABLED] = F(u64::from((lower || upper) && parent != 0));
    for half in 0..2 {
        let bank = &mut row[COMPARE + half * COMPARE_WIDTH..COMPARE + (half + 1) * COMPARE_WIDTH];
        let left = cell * 16 + half as u64 * 8;
        let mut borrow = 0_i64;
        for limb in 0..5 {
            let difference = u64::cast_signed((left >> (limb * 8)) & 255)
                - u64::cast_signed((end >> (limb * 8)) & 255)
                - borrow;
            borrow = i64::from(difference < 0);
            bits(
                &mut bank[limb * 8..(limb + 1) * 8],
                difference.rem_euclid(256) as u64,
            );
            bank[40 + limb] = F(i64::cast_unsigned(borrow));
        }
    }
    Ok(())
}
