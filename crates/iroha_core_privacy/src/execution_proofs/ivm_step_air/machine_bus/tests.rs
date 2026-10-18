//! Complete tuple, coherent RAM-forgery, staging, degree and native proof controls.

mod native;

use super::*;
use packet::{Event, Space};

fn bytes(value: u128) -> [u8; 16] {
    value.to_le_bytes()
}

fn event(space: Space, index: u32, before: u128, after: u128) -> Event {
    Event {
        space,
        vm: 0,
        generation: if space == Space::Initialization { 1 } else { 0 },
        index,
        write: before != after,
        before: bytes(before),
        after: bytes(after),
        before_private: 0,
        after_private: 0,
    }
}

fn fixture() -> PublicPacketBus {
    let mut write = event(Space::Memory, 0x0030_0000 / 16, 0, u128::MAX - 15);
    write.after_private = u16::MAX;
    let mut read = write.clone();
    read.before = read.after;
    read.before_private = read.after_private;
    read.write = false;
    let mut clear = read.clone();
    clear.write = true;
    clear.after_private = 0;
    let mut register = event(Space::Register, 255, 0, u128::from(u64::MAX));
    register.after_private = 1;
    PublicPacketBus::new(vec![
        Some(write),
        None,
        Some(register),
        Some(event(
            Space::Initialization,
            0x0030_0000 / 16,
            0,
            u128::from(u16::MAX),
        )),
        Some(event(Space::Owner, 4, 0, u128::from(u64::MAX))),
        Some(read),
        Some(clear),
        Some(event(Space::Memory, u32::MAX, 0, 3)),
    ])
    .unwrap()
}

fn challenges() -> permutation::Challenges {
    permutation::Challenges::testing(
        E::canonical([2, 1, 0, 0]).unwrap(),
        E::canonical([7, 0, 1, 0]).unwrap(),
    )
}

fn aux(columns: &[Vec<F>], challenge: &permutation::Challenges) -> Vec<Vec<F>> {
    let start = NOTE_COPY_WIDTH_V1;
    permutation::columns(
        &columns[start + ORDERED..start + SORTED],
        &columns[start + SORTED..start + PREVIOUS],
        challenge,
        columns[0].len(),
    )
    .unwrap()
}

fn row(columns: &[Vec<F>], index: usize, skip: usize) -> Vec<F> {
    columns[skip..].iter().map(|column| column[index]).collect()
}

fn failures(
    bus: &PublicPacketBus,
    columns: &[Vec<F>],
    challenge: &permutation::Challenges,
) -> usize {
    let aux = aux(columns, challenge);
    (0..bus.size())
        .filter(|index| {
            let next = (index + 1) % bus.size();
            residues(
                &row(columns, *index, NOTE_COPY_WIDTH_V1),
                &row(columns, next, NOTE_COPY_WIDTH_V1),
                &row(&aux, *index, 0),
                &row(&aux, next, 0),
                &bus.fixed(*index),
                challenge,
            )
            .iter()
            .any(|value| *value != F::ZERO)
        })
        .count()
}

#[test]
fn typed_cells_holes_private_masks_and_full_width_values_are_consistent() {
    for bus in [fixture(), PublicPacketBus::new(Vec::new()).unwrap()] {
        assert_eq!(failures(&bus, &bus.columns(), &challenges()), 0);
    }
    let mut boundary = event(Space::Owner, u32::MAX, 0, u128::from(u64::MAX));
    boundary.vm = u8::MAX;
    boundary.generation = u16::MAX;
    let bus = PublicPacketBus::new(vec![Some(boundary)]).unwrap();
    assert_eq!(failures(&bus, &bus.columns(), &challenges()), 0);
}

#[test]
fn coherently_claimed_nonzero_first_state_bad_reads_and_invalid_typed_bits_fail() {
    let mut cases = vec![
        event(Space::Memory, 4, 1, 2),
        event(Space::Register, 256, 0, 1),
        event(Space::Register, 3, 0, 1_u128 << 64),
        event(Space::Initialization, 4, 0, 1 << 16),
        event(Space::Owner, 3, 0, 1_u128 << 64),
    ];
    let mut read_changes = event(Space::Memory, 4, 0, 1);
    read_changes.write = false;
    cases.push(read_changes);
    let mut private_read = event(Space::Memory, 4, 0, 0);
    private_read.after_private = 1;
    cases.push(private_read);
    for space in [Space::Register, Space::Initialization, Space::Owner] {
        let mut bad = event(space, 4, 0, 1);
        bad.after_private = if space == Space::Register { 2 } else { 1 };
        cases.push(bad);
    }
    let mut wrong_generation = event(Space::Memory, 4, 0, 1);
    wrong_generation.generation = 1;
    cases.push(wrong_generation);
    for bad in cases {
        let bus = PublicPacketBus::new(vec![Some(bad)]).unwrap();
        assert!(failures(&bus, &bus.columns(), &challenges()) > 0);
    }
}

#[test]
fn coherent_continuity_forgery_cannot_change_value_or_private_mask_between_events() {
    for tag in [false, true] {
        let first = event(Space::Memory, 17, 0, 9);
        let mut second = event(Space::Memory, 17, 9, 9);
        if tag {
            second.before_private = 1;
            second.after_private = 1;
        } else {
            second.before = bytes(10);
            second.after = bytes(10);
        }
        let bus = PublicPacketBus::new(vec![Some(first), Some(second)]).unwrap();
        assert!(failures(&bus, &bus.columns(), &challenges()) > 0);
    }
}

#[test]
fn sorted_substitution_duplicate_clock_and_disabled_gap_are_rejected() {
    let bus = fixture();
    let mut sorted = (0..bus.events.len())
        .filter(|slot| bus.events[*slot].is_some())
        .map(|slot| bus.ordered(slot))
        .collect::<Vec<_>>();
    sorted.sort_unstable_by_key(|packet| (packet[packet::KEY].0, packet[packet::CLOCK].0));
    for attack in 0..6 {
        let mut forged = sorted.clone();
        match attack {
            0 => forged.swap(0, 1),
            1 => forged[1][packet::CLOCK] = forged[0][packet::CLOCK],
            2 => forged.insert(1, [F::ZERO; packet::WIDTH]),
            3 => {
                forged[0][packet::INDEX] = forged[0][packet::INDEX].add(F::ONE);
                forged[0][packet::KEY] = forged[0][packet::KEY].add(F::ONE);
            }
            4 => {
                forged.remove(0);
            }
            _ => {
                forged.insert(0, forged[0]);
            }
        }
        assert!(failures(&bus, &bus.witness_columns(&forged), &challenges()) > 0);
    }
}

#[test]
fn every_tuple_field_is_bound_by_the_post_commit_multiset_product() {
    let bus = fixture();
    let original = bus.columns();
    for field in 0..packet::WIDTH {
        let mut forged = original.clone();
        for phase in 0..PHASES {
            forged[NOTE_COPY_WIDTH_V1 + SORTED + field][phase] =
                forged[NOTE_COPY_WIDTH_V1 + SORTED + field][phase].add(F::ONE);
        }
        let values = aux(&forged, &challenges());
        let last = bus.size() - 1;
        assert_ne!(
            &row(&values, last, 0)[4..8],
            &row(&values, last, 0)[12..16],
            "unbound packet field {field}"
        );
    }
}

#[test]
fn every_profile_column_and_each_stage_is_constrained() {
    let bus = fixture();
    let columns = bus.columns();
    let challenge = challenges();
    let aux = aux(&columns, &challenge);
    for index in 0..PHASES {
        let next = index + 1;
        let base_row = row(&columns, index, NOTE_COPY_WIDTH_V1);
        let base_next = row(&columns, next, NOTE_COPY_WIDTH_V1);
        let aux_row = row(&aux, index, 0);
        let aux_next = row(&aux, next, 0);
        for column in 0..ROW_WIDTH + permutation::WIDTH {
            let mut changed_base = base_row.clone();
            let mut changed_aux = aux_row.clone();
            let value = if column < ROW_WIDTH {
                &mut changed_base[column]
            } else {
                &mut changed_aux[column - ROW_WIDTH]
            };
            *value = value.add(F::ONE);
            let current_fails = residues(
                &changed_base,
                &base_next,
                &changed_aux,
                &aux_next,
                &bus.fixed(index),
                &challenge,
            )
            .iter()
            .any(|value| *value != F::ZERO);
            let previous_fails = index > 0
                && residues(
                    &row(&columns, index - 1, NOTE_COPY_WIDTH_V1),
                    &changed_base,
                    &row(&aux, index - 1, 0),
                    &changed_aux,
                    &bus.fixed(index - 1),
                    &challenge,
                )
                .iter()
                .any(|value| *value != F::ZERO);
            assert!(
                current_fails || previous_fails,
                "stage {index}, column {column}"
            );
        }
    }
}

#[test]
fn last_domain_packet_constrains_after_products_and_completed_counts() {
    let mut events = vec![None; (1 << MIN_LOG) / PHASES];
    *events.last_mut().unwrap() = Some(event(Space::Memory, 9, 0, 17));
    let bus = PublicPacketBus::new(events).unwrap();
    let columns = bus.columns();
    let challenge = challenges();
    assert_eq!(failures(&bus, &columns, &challenge), 0);
    let aux = aux(&columns, &challenge);
    let last = bus.size() - 1;
    let base = row(&columns, last, NOTE_COPY_WIDTH_V1);
    let mut current = row(&aux, last, 0);
    assert_ne!(&current[..4], &current[8..12]);
    assert_eq!(&current[4..8], &current[12..16]);
    assert_eq!(base[ORDERED_COUNT], F::ZERO);
    assert_eq!(base[SORTED_COUNT], F::ONE);
    current[4] = current[4].add(F::ONE);
    assert!(
        residues(
            &base,
            &row(&columns, 0, NOTE_COPY_WIDTH_V1),
            &current,
            &row(&aux, 0, 0),
            &bus.fixed(last),
            &challenge,
        )
        .iter()
        .any(|value| *value != F::ZERO)
    );
}

#[test]
fn zero_challenges_and_zero_factors_follow_polynomial_constraints_without_inversion() {
    let bus = fixture();
    // Alpha=0 keeps the space coordinate; gamma=-1 makes memory factors zero.
    // This negligible transcript event is included in the compression error
    // bound; the implementation does not retry based on witness contents.
    let challenge = permutation::Challenges::testing(E::ZERO, E::ZERO.sub(E::ONE));
    let columns = bus.columns();
    assert_eq!(failures(&bus, &columns, &challenge), 0);
    let values = aux(&columns, &challenge);
    assert_eq!(&row(&values, bus.size() - 1, 0)[4..8], &[F::ZERO; 4]);
    assert_eq!(&row(&values, bus.size() - 1, 0)[12..16], &[F::ZERO; 4]);
    let mut forged = row(&values, PHASES - 1, 0);
    forged[4] = F::ONE;
    assert!(
        residues(
            &row(&columns, PHASES - 1, NOTE_COPY_WIDTH_V1),
            &row(&columns, PHASES, NOTE_COPY_WIDTH_V1),
            &forged,
            &row(&values, PHASES, 0),
            &bus.fixed(PHASES - 1),
            &challenge,
        )
        .iter()
        .any(|value| *value != F::ZERO)
    );
}
