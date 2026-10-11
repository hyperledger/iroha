//! Deterministic compact placement from the complete unknown Omega source.
//!
//! The larger scratch synthesis measures fixed source occupancy only. The returned
//! program always replays at k16; failure never selects a larger proof domain.

use ff::Field;
use iroha_pasta::Fq;
use iroha_plonk::frontend::{Circuit, synthesize};
use iroha_plonk_gadgets::range::secondary::{SecondaryPhase, SecondaryPlan};
use iroha_plonk_recursion::verifier::CompactSpans;

use super::{Error, Layout, OmegaCircuit};

const PREFIX: usize = 37;
const TRACE_K: u32 = 18;
const PROOF_K: u32 = 16;
const USABLE: usize = 65_530;
const SPONGE_END: usize = 32_768;
const ARITHMETIC_END: usize = 131_072;
const TRACE_END: usize = 262_138;
const ADVICE_COLUMNS: usize = 11;
const FIXED_COLUMNS: usize = 12;
const RANGE_START: usize = 16;
const RANGE_RADIX: usize = 15;
const RANGE_MAX: usize = 252;
const DIRECT_COLUMNS: usize = 3;
const SPARE_POSEIDON: [usize; 6] = [0, 1, 2, 4, 5, 9];
const SPARE_GLUE: [usize; 6] = [4, 5, 6, 7, 8, 9];

/// Canonical compiled Omega placement-policy preimage for the signed native
/// profile. Frames the fixed trace/proof domains, source columns/range tape,
/// reserved prefix and exact spare-port rule followed by the shared planner ID.
/// This identifies the recipe; exact source and original-key qualification remain
/// mandatory and cannot be replaced by its digest.
///
/// # Errors
/// A compiled layout constant cannot be represented by the fixed LE32 framing.
pub fn compiled_policy_transcript() -> Result<Vec<u8>, Error> {
    let mut out = b"iroha-kagemusha-omega-layout-v1\0".to_vec();
    out.extend_from_slice(&PROOF_K.to_le_bytes());
    out.extend_from_slice(&TRACE_K.to_le_bytes());
    for value in [
        PREFIX,
        USABLE,
        SPONGE_END,
        ARITHMETIC_END,
        TRACE_END,
        ADVICE_COLUMNS,
        FIXED_COLUMNS,
        RANGE_START,
        RANGE_RADIX,
        RANGE_MAX,
        SPARE_POSEIDON.len(),
    ]
    .into_iter()
    .chain(SPARE_POSEIDON)
    .chain([SPARE_GLUE.len()])
    .chain(SPARE_GLUE)
    .chain([DIRECT_COLUMNS])
    {
        out.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| Error::Artifact)?
                .to_le_bytes(),
        );
    }
    out.extend_from_slice(b"SecondaryPlan::new/v1\0");
    Ok(out)
}

/// Decode every exact range request from the fixed primary tuple tape.
fn range_widths(pattern: &[Fq], tops: &[Fq], end: usize) -> Result<Vec<usize>, Error> {
    if end < RANGE_START || end > pattern.len() || end > tops.len() {
        return Err(Error::Artifact);
    }
    let mut widths = Vec::new();
    let mut row = RANGE_START;
    while row < end {
        let start = row;
        while row < end && pattern[row] == Fq::ONE {
            row += 1;
        }
        if row == end {
            return Err(Error::Artifact);
        }
        let top = if pattern[row] == Fq::from(3) {
            1
        } else if pattern[row] == Fq::from(4) {
            2
        } else if pattern[row] == Fq::from(2) {
            (3_u32..=15)
                .find(|bits| tops[row] == Fq::from(u64::from(*bits)))
                .map(|bits| bits as usize)
                .ok_or(Error::Artifact)?
        } else {
            return Err(Error::Artifact);
        };
        let bits = (row - start)
            .checked_mul(RANGE_RADIX)
            .and_then(|n| n.checked_add(top))
            .filter(|bits| *bits <= RANGE_MAX)
            .ok_or(Error::Artifact)?;
        widths.push(bits);
        row += 1;
    }
    Ok(widths)
}

pub(super) fn derive(source: &OmegaCircuit) -> Result<Layout, Error> {
    let trace_spans =
        CompactSpans::new(SPONGE_END, ARITHMETIC_END, TRACE_END).map_err(|_| Error::Artifact)?;
    let trace = source.without_witnesses().with_compact_layout(trace_spans);
    let assigned = synthesize(&trace, TRACE_K, None).map_err(|_| Error::Artifact)?;
    let advice = assigned.tables.advice_assigned();
    let fixed = assigned.tables.fixed();
    let occupied_fixed = assigned.tables.fixed_assigned();
    if advice.len() != ADVICE_COLUMNS
        || fixed.len() != FIXED_COLUMNS
        || occupied_fixed.len() != FIXED_COLUMNS
    {
        return Err(Error::Artifact);
    }
    let used = |start: usize, end: usize| {
        advice[..10]
            .iter()
            .filter_map(|column| {
                column[start..end]
                    .iter()
                    .rposition(|cell| *cell)
                    .map(|r| r + 1)
            })
            .max()
            .unwrap_or(0)
    };
    let sponge = used(0, SPONGE_END).div_ceil(PREFIX) * PREFIX;
    let arithmetic = used(SPONGE_END, ARITHMETIC_END);
    let curve = used(ARITHMETIC_END, TRACE_END);
    let total = sponge + arithmetic + curve + PREFIX;
    if total > USABLE {
        return Err(Error::Artifact);
    }
    let padding = USABLE - total;
    let range_end = advice[10]
        .iter()
        .rposition(|cell| *cell)
        .map_or(0, |r| r + 1);
    let widths = range_widths(&fixed[11], &fixed[10], range_end)?;
    let mut phases = vec![None; USABLE];
    for (packed, row) in (0..sponge)
        .chain(SPONGE_END..SPONGE_END + arithmetic)
        .enumerate()
    {
        let high = fixed[1][row] == Fq::ONE;
        let low = fixed[0][row] == Fq::ONE;
        let active = occupied_fixed[0][row] && occupied_fixed[1][row];
        let ports = if high { &SPARE_POSEIDON } else { &SPARE_GLUE };
        // The original direct-public cells move behind the reserved prefix.
        // All other live cells remain unavailable to the secondary range bus.
        let free = ports
            .iter()
            .all(|column| !advice[*column][row] || row < RANGE_START && *column < DIRECT_COLUMNS);
        if active && (high || !low) && !free {
            return Err(Error::Artifact);
        }
        if free && (high || !low) {
            phases[packed + PREFIX] = Some(if high {
                if low {
                    SecondaryPhase::PairedPoseidon
                } else {
                    SecondaryPhase::Poseidon
                }
            } else {
                SecondaryPhase::Glue
            });
        }
    }
    let padding_start = sponge + arithmetic + PREFIX;
    phases[padding_start..padding_start + padding].fill(Some(SecondaryPhase::Glue));
    let schedule = SecondaryPlan::new(widths, phases).map_err(|_| Error::Artifact)?;
    let spans = CompactSpans::new(sponge + PREFIX, padding_start + padding, USABLE)
        .map_err(|_| Error::Artifact)?;
    drop(assigned);
    // Secondary replay checks the exact event sequence and shared-cell ownership.
    // This unknown assignment establishes source shape only, never proof validity.
    let replay = source
        .without_witnesses()
        .with_secondary_layout(spans, schedule.clone());
    synthesize(&replay, PROOF_K, None).map_err(|_| Error::Artifact)?;
    Ok(Layout::Secondary { spans, schedule })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_policy_has_exact_unambiguous_framing() {
        let mut expected = b"iroha-kagemusha-omega-layout-v1\0".to_vec();
        for word in [
            16_u32, 18, 37, 65_530, 32_768, 131_072, 262_138, 11, 12, 16, 15, 252, 6, 0, 1, 2, 4,
            5, 9, 6, 4, 5, 6, 7, 8, 9, 3,
        ] {
            expected.extend_from_slice(&word.to_le_bytes());
        }
        expected.extend_from_slice(b"SecondaryPlan::new/v1\0");
        assert_eq!(compiled_policy_transcript().unwrap(), expected);
    }

    #[test]
    fn complete_range_tape_retains_order_and_exact_top_widths() {
        let mut pattern = vec![Fq::ZERO; 16];
        pattern.extend([Fq::from(3), Fq::from(4), Fq::ONE, Fq::from(2)]);
        let mut tops = vec![Fq::ZERO; 20];
        tops[19] = Fq::from(7);
        assert_eq!(range_widths(&pattern, &tops, 20).unwrap(), [1, 2, 22]);
        assert_eq!(range_widths(&pattern, &tops, 16).unwrap(), []);
    }

    #[test]
    fn malformed_range_tapes_fail_without_partial_schedule() {
        let mut pattern = vec![Fq::ZERO; 16];
        pattern.extend([Fq::ONE, Fq::from(2)]);
        let mut tops = vec![Fq::ZERO; 18];
        tops[17] = Fq::from(15);
        assert_eq!(range_widths(&pattern, &tops, 18).unwrap(), [30]);
        for end in [0, 15, 17, 19, usize::MAX] {
            assert_eq!(range_widths(&pattern, &tops, end), Err(Error::Artifact));
        }
        tops[17] = Fq::from(16);
        assert_eq!(range_widths(&pattern, &tops, 18), Err(Error::Artifact));
        pattern[17] = Fq::ZERO;
        assert_eq!(range_widths(&pattern, &tops, 18), Err(Error::Artifact));
        pattern[16..].fill(Fq::ONE);
        assert_eq!(range_widths(&pattern, &tops, 18), Err(Error::Artifact));
        pattern.resize(34, Fq::ONE);
        pattern.push(Fq::from(3));
        tops.resize(35, Fq::ZERO);
        assert_eq!(range_widths(&pattern, &tops, 35), Err(Error::Artifact));
    }
}
