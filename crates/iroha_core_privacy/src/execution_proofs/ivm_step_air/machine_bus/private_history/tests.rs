//! Public-geometry invariance, original producer binding and private-count history.

use super::*;
use packet::{Event, Space};

fn event(before: u64, after: u64, write: bool) -> Event {
    Event {
        space: Space::Owner,
        vm: 7,
        generation: 3,
        index: 9,
        write,
        before: u128::from(before).to_le_bytes(),
        after: u128::from(after).to_le_bytes(),
        before_private: 0,
        after_private: 0,
    }
}

fn challenges() -> permutation::Challenges {
    permutation::Challenges::testing(
        E::canonical([2, 1, 0, 0]).unwrap(),
        E::canonical([7, 0, 1, 0]).unwrap(),
    )
}

fn failures(bus: &PublicPacketBus, columns: &[Vec<F>]) -> usize {
    let schedule = Schedule::new(bus.trace_log2, 1).unwrap();
    let challenge = challenges();
    let aux = permutation::columns(
        &columns[NOTE_COPY_WIDTH_V1 + ORDERED..NOTE_COPY_WIDTH_V1 + SORTED],
        &columns[NOTE_COPY_WIDTH_V1 + SORTED..NOTE_COPY_WIDTH_V1 + PREVIOUS],
        &challenge,
        bus.size(),
    )
    .unwrap();
    (0..bus.size())
        .filter(|index| {
            let next_index = (index + 1) % bus.size();
            let row = core::array::from_fn(|column| columns[NOTE_COPY_WIDTH_V1 + column][*index]);
            let next =
                core::array::from_fn(|column| columns[NOTE_COPY_WIDTH_V1 + column][next_index]);
            let aux_row = aux.iter().map(|column| column[*index]).collect::<Vec<_>>();
            let aux_next = aux
                .iter()
                .map(|column| column[next_index])
                .collect::<Vec<_>>();
            let mut output = Vec::new();
            append_residues(
                &mut output,
                &row,
                &next,
                &aux_row,
                &aux_next,
                &schedule.fixed(*index).unwrap(),
                &bus.ordered(*index / PHASES),
                &challenge,
            );
            assert_eq!(output.len(), CONSTRAINTS);
            output.into_iter().any(|value| value != F::ZERO)
        })
        .count()
}

#[test]
fn distinct_private_events_and_activity_counts_share_identical_public_geometry() {
    let empty = PublicPacketBus::new(Vec::new()).unwrap();
    let one = PublicPacketBus::new(vec![Some(event(0, 123, true))]).unwrap();
    let three = PublicPacketBus::new(vec![
        Some(event(0, 456, true)),
        None,
        Some(event(456, 456, false)),
        Some(event(456, 789, true)),
    ])
    .unwrap();
    for bus in [&empty, &one, &three] {
        assert_eq!(bus.trace_log2, MIN_LOG);
        let schedule = Schedule::new(bus.trace_log2, 1).unwrap();
        for index in 0..schedule.size() {
            let fixed = schedule.fixed(index).unwrap();
            assert!(fixed[..packet::WIDTH].iter().all(|field| *field == F::ZERO));
            assert_eq!(fixed[TOTAL], F::ZERO);
            assert_eq!(
                fixed,
                Schedule::new(empty.trace_log2, 1)
                    .unwrap()
                    .fixed(index)
                    .unwrap()
            );
        }
        assert_eq!(failures(bus, &bus.columns()), 0);
    }
    assert!(Schedule::new(MIN_LOG - 1, 1).is_none());
    assert!(Schedule::new(MAX_LOG + 1, 1).is_none());
    assert!(
        Schedule::new(MAX_LOG, 1)
            .unwrap()
            .fixed(1 << MAX_LOG)
            .is_none()
    );
}

#[test]
fn coherent_history_cannot_replace_an_original_committed_producer_tuple() {
    let original = PublicPacketBus::new(vec![
        Some(event(0, 9, true)),
        None,
        Some(event(9, 9, false)),
    ])
    .unwrap();
    let forged = PublicPacketBus::new(vec![
        Some(event(0, 10, true)),
        None,
        Some(event(10, 10, false)),
    ])
    .unwrap();
    assert_eq!(original.trace_log2, forged.trace_log2);
    assert_eq!(failures(&forged, &forged.columns()), 0);
    // Recomputed sorting, continuity and permutation products do not replace
    // the original semantic producer port in the shared relation.
    assert!(failures(&original, &forged.columns()) > 0);
    let mut missing = original.columns();
    for index in PHASES * 2..PHASES * 3 {
        missing[NOTE_COPY_WIDTH_V1 + ORDERED + packet::ENABLED][index] = F::ZERO;
    }
    assert!(failures(&original, &missing) > 0);
}

#[test]
fn private_history_retains_first_state_read_preservation_and_terminal_counts() {
    for inputs in [
        vec![Some(event(1, 2, true))],
        vec![Some(event(0, 1, true)), Some(event(1, 2, false))],
    ] {
        let bus = PublicPacketBus::new(inputs).unwrap();
        assert!(failures(&bus, &bus.columns()) > 0);
    }
    let valid = PublicPacketBus::new(vec![Some(event(0, 7, true))]).unwrap();
    let mut changed = valid.columns();
    changed[NOTE_COPY_WIDTH_V1 + SORTED_COUNT][valid.size() - 1] = F(2);
    assert!(failures(&valid, &changed) > 0);
}

#[test]
fn private_producer_and_count_binding_preserve_degree_four() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let challenge = challenges();
    assert_eq!(
        measured_maximum_affine_degree_v1(
            [0x94; 32],
            [
                ROW_WIDTH + packet::WIDTH,
                ROW_WIDTH,
                permutation::WIDTH,
                permutation::WIDTH,
                FIXED_WIDTH
            ],
            3,
            4,
            |row, next, aux, next_aux, fixed| {
                let mut output = Vec::new();
                append_residues(
                    &mut output,
                    row[..ROW_WIDTH].try_into().unwrap(),
                    next.try_into().unwrap(),
                    aux,
                    next_aux,
                    fixed.try_into().unwrap(),
                    row[ROW_WIDTH..].try_into().unwrap(),
                    &challenge,
                );
                Ok::<_, Error>(output)
            }
        ),
        4
    );
}
