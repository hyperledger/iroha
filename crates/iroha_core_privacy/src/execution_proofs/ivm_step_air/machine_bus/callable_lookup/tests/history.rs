//! Original-clock window joins; arbitrary initializers remain test inputs only.

use super::super::super::{
    E, NOTE_COPY_WIDTH_V1, ORDERED, PREVIOUS, PublicPacketBus, ROW_WIDTH, SORTED, permutation,
    private_history,
};
use super::*;

fn as_event(fields: &[F; packet::WIDTH]) -> Option<packet::Event> {
    (fields[ENABLED] == F::ONE).then(|| packet::Event {
        space: match fields[packet::SPACE].0 {
            1 => Space::Memory,
            2 => Space::Register,
            3 => Space::Initialization,
            4 => Space::Owner,
            _ => panic!("original packet space"),
        },
        vm: fields[packet::VM].0 as u8,
        generation: fields[GENERATION].0 as u16,
        index: fields[packet::INDEX].0 as u32,
        write: fields[packet::WRITE] == F::ONE,
        before: core::array::from_fn(|index| {
            (fields[BEFORE + index / 2].0 >> (8 * (index % 2))) as u8
        }),
        after: core::array::from_fn(|index| {
            (fields[packet::AFTER + index / 2].0 >> (8 * (index % 2))) as u8
        }),
        before_private: fields[packet::BEFORE_TAG].0 as u16,
        after_private: fields[packet::AFTER_TAG].0 as u16,
    })
}

struct History {
    columns: Vec<Vec<F>>,
    aux: Vec<Vec<F>>,
    schedule: private_history::Schedule,
    challenges: permutation::Challenges,
}
impl History {
    fn new(fixture: &Fixture) -> Self {
        Self::many(&[fixture])
    }
    fn many(fixtures: &[&Fixture]) -> Self {
        let last_clock = fixtures
            .iter()
            .map(|fixture| fixture.schedule.first as usize + CLOCK_SLOTS)
            .max()
            .unwrap();
        let first_clock = fixtures
            .iter()
            .map(|fixture| fixture.schedule.first)
            .min()
            .unwrap();
        let mut events = vec![None; last_clock];
        let mut initial = std::collections::BTreeMap::new();
        for fixture in fixtures {
            for offset in 0..CLOCK_SLOTS {
                let original = fixture.schedule.producer_at_clock(&fixture.packets, offset);
                let event = as_event(original);
                if let Some(event) = &event {
                    assert_eq!(
                        original[CLOCK],
                        F(u64::from(fixture.schedule.first) + offset as u64)
                    );
                    initial
                        .entry((event.vm, event.space as u8, event.generation, event.index))
                        .or_insert_with(|| packet::Event {
                            space: event.space,
                            vm: event.vm,
                            generation: event.generation,
                            index: event.index,
                            write: true,
                            before: [0; 16],
                            after: event.before,
                            before_private: 0,
                            after_private: event.before_private,
                        });
                }
                events[fixture.schedule.first as usize + offset] = event;
            }
        }
        // Candidate first-state writes make a local consistency oracle. They are
        // not authenticated root/State initialization and confer no authority.
        let initial = initial
            .into_values()
            .filter(|event| event.after != [0; 16] || event.after_private != 0);
        for (index, event) in initial.enumerate() {
            assert!(index < first_clock as usize);
            events[index] = Some(event);
        }
        let trace_log2 = (events.len() * 8).next_power_of_two().ilog2() as u8;
        assert!((17..=18).contains(&trace_log2));
        let segments = if trace_log2 == 18 { 2 } else { 1 };
        // Reuse only the algebraic column oracle at the requested candidate
        // size. This deliberately is not PublicPacketBus::new/protocol/prove:
        // that unchanged single-segment profile rejects more than 16,384 slots.
        let bus = PublicPacketBus {
            total: events.iter().filter(|event| event.is_some()).count(),
            events,
            trace_log2,
        };
        let columns = bus.columns();
        let challenges = permutation::Challenges::testing(
            E::canonical([2, 1, 0, 0]).unwrap(),
            E::canonical([7, 0, 1, 0]).unwrap(),
        );
        let aux = permutation::columns(
            &columns[NOTE_COPY_WIDTH_V1 + ORDERED..NOTE_COPY_WIDTH_V1 + SORTED],
            &columns[NOTE_COPY_WIDTH_V1 + SORTED..NOTE_COPY_WIDTH_V1 + PREVIOUS],
            &challenges,
            bus.size(),
        )
        .unwrap();
        Self {
            columns,
            aux,
            schedule: private_history::Schedule::new(17, segments).unwrap(),
            challenges,
        }
    }
    fn view(&self) -> private_history::View<'_> {
        let size = self.schedule.segment_size();
        private_history::View::new(
            self.schedule,
            (0..self.schedule.size() / size).map(|segment| {
                let range = segment * size..(segment + 1) * size;
                private_history::Segment::new(
                    core::array::from_fn(|index| {
                        &self.columns[NOTE_COPY_WIDTH_V1 + index][range.clone()]
                    }),
                    core::array::from_fn(|index| &self.aux[index][range.clone()]),
                )
            }),
            &self.challenges,
        )
        .unwrap()
    }
    fn accepts_row(&self, index: usize, producer: &[F; packet::WIDTH]) -> bool {
        let mut scratch = Scratch::new();
        let mut check = |values: &[F]| {
            if values.iter().all(|value| *value == F::ZERO) {
                Ok(())
            } else {
                Err(())
            }
        };
        let mut out = Stream::new(&mut scratch, &mut check);
        self.view().append_row(&mut out, index, producer);
        out.finish().is_ok()
    }
}

#[test]
fn complete_scan_and_original_window_compose_without_reclocking_or_row_lists() {
    for (program, slot, first, start) in [
        (program(), 0, 100, ivm::Memory::STACK_START),
        (program(), 4, 100, ivm::Memory::STACK_START),
        (
            maximum_result_program(),
            4,
            5000,
            ivm::Memory::STACK_START + 8,
        ),
    ] {
        let fixture = Fixture::at(&program, Some(slot), false, first, start);
        if first == 5000 {
            // The shifted 64-KiB table touches every cell; both original ports
            // are enabled for all 4,097 child/immediate-parent pairs.
            assert!(
                (FIXED_PORTS..PORTS)
                    .all(|index| { fixture.packets.producer(index).unwrap()[ENABLED] == F::ONE })
            );
        }
        let history = History::new(&fixture);
        let mut controls = 0;
        let mut scans = 0;
        let mut rows = 0;
        evaluate(
            &program,
            &fixture.schedule,
            fixture.witness(),
            &fixture.packets,
            &history.view(),
            |row, values| {
                match row {
                    Row::Control => controls += 1,
                    Row::Scan(index) => {
                        assert_eq!(index, scans);
                        scans += 1;
                    }
                    Row::History(index) => {
                        assert_eq!(index, fixture.schedule.first as usize * 8 + rows);
                        rows += 1;
                    }
                }
                if values.iter().all(|value| *value == F::ZERO) {
                    Ok(())
                } else {
                    Err(row)
                }
            },
        )
        .unwrap();
        assert!(controls > 0);
        assert_eq!(scans, 4097);
        assert_eq!(rows, 66_376);
        for offset in 0..CLOCK_SLOTS {
            let producer = fixture.schedule.producer_at_clock(&fixture.packets, offset);
            if producer[ENABLED] == F::ONE {
                assert_eq!(
                    producer[CLOCK],
                    F(u64::from(fixture.schedule.first) + offset as u64)
                );
            }
        }
    }
}

#[test]
fn original_tuples_gap_zeros_and_derived_adjacency_reject_tampering() {
    let program = program();
    let fixture = Fixture::new(&program, Some(4), false);
    let mut history = History::new(&fixture);
    for offset in [
        0, 15, 19, 20, 21, 45, 46, 47, 100, 101, 4196, 4197, 8292, 8293, 8296,
    ] {
        let original = fixture.schedule.producer_at_clock(&fixture.packets, offset);
        let row = (fixture.schedule.first as usize + offset) * 8;
        assert!(
            history.accepts_row(row, original),
            "original offset={offset}"
        );
        for column in 0..packet::WIDTH {
            let mut changed = *original;
            changed[column] = changed[column].add(F::ONE);
            assert!(
                !history.accepts_row(row, &changed),
                "offset={offset}, column={column}"
            );
        }
    }
    for offset in [22, 29, 54, 99] {
        let row = (fixture.schedule.first as usize + offset) * 8;
        let column = NOTE_COPY_WIDTH_V1 + ORDERED + BEFORE;
        history.columns[column][row] = F::ONE;
        assert!(!history.accepts_row(row, &[F::ZERO; packet::WIDTH]));
        history.columns[column][row] = F::ZERO;
    }
    let offset = 100;
    let row = (fixture.schedule.first as usize + offset) * 8;
    let producer = fixture.schedule.producer_at_clock(&fixture.packets, offset);
    let column = NOTE_COPY_WIDTH_V1 + ORDERED + BEFORE;
    let original = history.columns[column][row + 1];
    history.columns[column][row + 1] = original.add(F::ONE);
    assert!(!history.accepts_row(row, producer));
    history.columns[column][row + 1] = original;
    history.aux[0][row + 1] = history.aux[0][row + 1].add(F::ONE);
    assert!(!history.accepts_row(row, producer));
}

#[test]
fn impossible_geometry_and_consumer_failure_cannot_report_completion() {
    let program = program();
    let fixture = Fixture::new(&program, None, false);
    let schedule = private_history::Schedule::new(13, 1).unwrap();
    let column = vec![F::ZERO; schedule.size()];
    let challenges = permutation::Challenges::testing(E::ONE, E::ONE);
    let view = private_history::View::new(
        schedule,
        [private_history::Segment::new(
            [column.as_slice(); ROW_WIDTH],
            [column.as_slice(); permutation::WIDTH],
        )],
        &challenges,
    )
    .unwrap();
    let result = evaluate(
        &program,
        &fixture.schedule,
        fixture.witness(),
        &fixture.packets,
        &view,
        |_, _| -> Result<(), ()> { panic!("invalid geometry reached evaluation") },
    );
    assert_eq!(
        result,
        Err(EvaluationError::History(
            private_history::ShapeError::Window
        ))
    );
    let column = vec![F::ZERO; 1 << 17];
    let view = private_history::View::new(
        private_history::Schedule::new(17, 1).unwrap(),
        [private_history::Segment::new(
            [column.as_slice(); ROW_WIDTH],
            [column.as_slice(); permutation::WIDTH],
        )],
        &challenges,
    )
    .unwrap();
    let mut calls = 0;
    let result = evaluate(
        &program,
        &fixture.schedule,
        fixture.witness(),
        &fixture.packets,
        &view,
        |row, _| {
            calls += 1;
            assert_eq!(row, Row::Control);
            Err(9)
        },
    );
    assert_eq!(result, Err(EvaluationError::Consumer(9)));
    assert_eq!(calls, 1);
}

#[test]
fn two_maximum_return_windows_share_original_segmented_columns_and_clocks() {
    let program = maximum_result_program();
    // Distinct VM spaces give two independent component returns one shared
    // ordered/sorted history. Their test initializers confer no invocation or
    // native producer authority; this is not a complete execution fixture.
    let first = Fixture::at_vm(
        &program,
        Some(4),
        false,
        9_000,
        ivm::Memory::STACK_START + 8,
        7,
    );
    let second = Fixture::at_vm(
        &program,
        Some(4),
        false,
        18_000,
        ivm::Memory::STACK_START + 8,
        8,
    );
    let history = History::many(&[&first, &second]);
    assert_eq!(history.schedule.size(), 262_144);
    let view = history.view();
    for fixture in [&first, &second] {
        assert!(
            (FIXED_PORTS..PORTS)
                .all(|index| fixture.packets.producer(index).unwrap()[ENABLED] == F::ONE)
        );
        let mut scans = 0;
        let mut rows = 0;
        evaluate(
            &program,
            &fixture.schedule,
            fixture.witness(),
            &fixture.packets,
            &view,
            |row, values| {
                match row {
                    Row::Control => {}
                    Row::Scan(index) => {
                        assert_eq!(index, scans);
                        scans += 1;
                    }
                    Row::History(index) => {
                        assert_eq!(index, fixture.schedule.first as usize * 8 + rows);
                        rows += 1;
                    }
                }
                if values.iter().all(|value| *value == F::ZERO) {
                    Ok(())
                } else {
                    Err(row)
                }
            },
        )
        .unwrap();
        assert_eq!(scans, 4_097);
        assert_eq!(rows, 66_376);
    }
    // The first window straddles the actual segment seam; it cannot reinterpret
    // the second segment's first producer as a zero-based local clock.
    let offset = 16_384 - first.schedule.first as usize;
    let producer = first.schedule.producer_at_clock(&first.packets, offset);
    assert_eq!(producer[CLOCK], F(16_384));
    assert!(history.accepts_row(16_384 * 8, producer));
    let mut rebased = *producer;
    rebased[CLOCK] = F::ZERO;
    assert!(!history.accepts_row(16_384 * 8, &rebased));
}
