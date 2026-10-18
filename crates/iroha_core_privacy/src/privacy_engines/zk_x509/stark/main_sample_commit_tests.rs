//! Bounded first-pass source, entropy, polynomial and commitment controls.

use super::*;
use crate::privacy_engines::zk_x509::private_table::inspection;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::cell::{Cell, RefCell};

fn native(log: u8, column: usize) -> ZeroizingMainTraceColumnV1 {
    ZeroizingMainTraceColumnV1(
        (0..1_usize << log)
            .map(|row| F::reduce(17 + 31 * column as u128 + 7 * row as u128))
            .collect(),
    )
}

fn cpu(words: &mut [Vec<u64>], root: u64, direction: Direction) -> Result<Backend, TransformError> {
    assert_eq!(direction, Direction::Inverse);
    transform_goldilocks_columns_v1(words, root, direction, fastpq_prover::ExecutionMode::Cpu)
}

#[test]
fn fused_sampling_preserves_complete_coefficients_masks_rng_and_tail_boundaries() {
    for log in [3, 11] {
        for width in [1, 7, 8, 9, 17] {
            let mut old_rng = StdRng::from_seed([log + 51; 32]);
            let mut new_rng = old_rng.clone();
            let reference =
                MainTraceMaskGroupV1::sample_v1(log, 13, width, &mut old_rng, |column| {
                    Ok(native(log, column))
                })
                .unwrap();
            let mut fused = MainTraceMaskGroupV1::empty_v1(log, 13, width).unwrap();
            let mut source_columns = Vec::new();
            for first in (0..width).step_by(8) {
                let end = width.min(first + 8);
                let actual = fused
                    .sample_and_replay_batch_with_v1(
                        first..end,
                        MainBoundedTransformPolicyV1::for_test_v1(1 << log, 4),
                        &mut new_rng,
                        |column| {
                            source_columns.push(column);
                            Ok(native(log, column))
                        },
                        cpu,
                        || false,
                    )
                    .unwrap();
                assert_eq!(actual.len(), end - first);
                for (column, coefficients) in (first..end).zip(actual) {
                    assert_eq!(
                        coefficients,
                        reference.replay_v1(column, &native(log, column)).unwrap()
                    );
                    assert_eq!(
                        fused.masks[column].coefficients(),
                        reference.masks[column].coefficients()
                    );
                }
            }
            assert_eq!(source_columns, (0..width).collect::<Vec<_>>());
            assert_eq!(new_rng.next_u64(), old_rng.next_u64());
        }
    }
}

struct OrderedEntropy<'a> {
    draws: usize,
    events: &'a RefCell<Vec<String>>,
    fail: Option<usize>,
    unwind: bool,
}
impl TryRngCore for OrderedEntropy<'_> {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(destination.len(), 8);
        if self.fail == Some(self.draws) {
            destination.fill(0x5a);
            assert!(!self.unwind, "injected entropy unwind");
            return Err(std::io::Error::other("injected entropy failure"));
        }
        if self.draws % (MASK_DEGREE + 1) == 0 {
            self.events
                .borrow_mut()
                .push(format!("mask{}", self.draws / (MASK_DEGREE + 1)));
        }
        destination.copy_from_slice(&(17 + self.draws as u64).to_le_bytes());
        self.draws += 1;
        Ok(())
    }
}

#[test]
fn fused_sampler_keeps_scalar_source_before_entropy_and_drops_source_owner_before_inverse() {
    struct SourceOwner<'a>(&'a Cell<bool>);
    impl Drop for SourceOwner<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    for batched in [false, true] {
        let events = RefCell::new(Vec::new());
        let released = Cell::new(false);
        let owner = SourceOwner(&released);
        let event_ref = &events;
        let mut pending = Vec::new().into_iter();
        let mut rng = OrderedEntropy {
            draws: 0,
            events: &events,
            fail: None,
            unwind: false,
        };
        let mut group = MainTraceMaskGroupV1::empty_v1(3, 13, 8).unwrap();
        let result = group
            .sample_and_replay_batch_with_v1(
                0..8,
                MainBoundedTransformPolicyV1::for_test_v1(8, 8),
                &mut rng,
                move |column| {
                    let _keep_whole_owner = &owner;
                    assert!(!owner.0.get());
                    if batched {
                        if column == 0 {
                            pending = (0..8)
                                .map(|index| {
                                    event_ref.borrow_mut().push(format!("source{index}"));
                                    native(3, index)
                                })
                                .collect::<Vec<_>>()
                                .into_iter();
                        }
                        Ok(pending.next().unwrap())
                    } else {
                        event_ref.borrow_mut().push(format!("source{column}"));
                        Ok(native(3, column))
                    }
                },
                |words, root, direction| {
                    assert!(
                        released.get(),
                        "source iterator allocation must have dropped before staging"
                    );
                    events.borrow_mut().push("inverse".into());
                    cpu(words, root, direction)
                },
                || false,
            )
            .unwrap();
        assert_eq!(result.len(), 8);
        let expected = if batched {
            (0..8)
                .map(|i| format!("source{i}"))
                .chain((0..8).map(|i| format!("mask{i}")))
                .collect::<Vec<_>>()
        } else {
            (0..8)
                .flat_map(|i| [format!("source{i}"), format!("mask{i}")])
                .collect::<Vec<_>>()
        };
        assert_eq!(&events.borrow()[..16], &expected);
        assert_eq!(events.borrow()[16], "inverse");
    }
}

#[test]
fn fused_errors_return_only_an_entropy_prefix_and_clear_resident_columns() {
    for failure in 0..8 {
        let events = RefCell::new(Vec::new());
        let mut rng = OrderedEntropy {
            draws: 0,
            events: &events,
            fail: None,
            unwind: false,
        };
        let uncertain = Cell::new(false);
        let calls = Cell::new(0);
        let (result, erased) = inspection::observe_v1(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut group = MainTraceMaskGroupV1::empty_v1(3, 13, 9).unwrap();
                for first in [0, 8] {
                    let _output = group.sample_and_replay_batch_with_v1(
                        first..9.min(first + 8),
                        MainBoundedTransformPolicyV1::for_test_v1(8, 8),
                        &mut rng,
                        |column| {
                            calls.set(calls.get() + 1);
                            Ok(native(3, column))
                        },
                        |words, _, _| match failure {
                            0 => Err(TransformError::DeviceUnavailable),
                            1 => Err(TransformError::CompletionUncertain),
                            2 => {
                                words[0][0] = u64::MAX;
                                Ok(Backend::Metal)
                            }
                            3 => {
                                words[0].pop();
                                Ok(Backend::Metal)
                            }
                            4 => Ok(Backend::Cuda),
                            5 => {
                                uncertain.set(true);
                                Ok(Backend::Cpu)
                            }
                            6 => panic!("injected first-pass transform unwind"),
                            _ => Err(TransformError::InvalidRoot),
                        },
                        || uncertain.get(),
                    )?;
                }
                Ok::<(), ZkX509StarkErrorV1>(())
            }))
        });
        if failure == 6 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(
            calls.get(),
            8,
            "ninth source must not execute after failed first batch"
        );
        assert_eq!(rng.draws, 8 * (MASK_DEGREE + 1));
        assert_eq!(
            erased.iter().map(|item| item.cells).sum::<usize>(),
            2 * 8 * 8
        );
        assert!(erased.iter().all(|item| item.nonzero_after == 0));
    }
}

#[test]
fn fused_partial_source_and_entropy_errors_and_unwinds_clear_all_owned_native_cells() {
    for source_failure in [true, false] {
        for unwind in [false, true] {
            let events = RefCell::new(Vec::new());
            let mut rng = OrderedEntropy {
                draws: 0,
                events: &events,
                fail: (!source_failure).then_some(2 * (MASK_DEGREE + 1) + 2),
                unwind,
            };
            let calls = Cell::new(0);
            let (result, erased) = inspection::observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut group = MainTraceMaskGroupV1::empty_v1(3, 13, 8).unwrap();
                    group.sample_and_replay_batch_with_v1(
                        0..8,
                        MainBoundedTransformPolicyV1::for_test_v1(8, 8),
                        &mut rng,
                        |column| {
                            calls.set(calls.get() + 1);
                            let value = native(3, column);
                            if source_failure && column == 2 {
                                assert!(!unwind, "injected source unwind");
                                return Err(ZkX509StarkErrorV1::AllocationFailure);
                            }
                            Ok(value)
                        },
                        |_, _, _| panic!("partial sampling must not dispatch"),
                        || false,
                    )
                }))
            });
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert_eq!(calls.get(), 3);
            assert_eq!(erased.iter().map(|item| item.cells).sum::<usize>(), 3 * 8);
            assert!(erased.iter().all(|item| item.nonzero_after == 0));
            assert_eq!(
                rng.draws,
                2 * (MASK_DEGREE + 1) + if source_failure { 0 } else { 2 }
            );
        }
    }
}

#[test]
fn fused_geometry_capacity_and_quarantine_reject_before_source_or_entropy() {
    for (native, common, width) in [
        (3, 3, 1),
        (3, 10, 1),
        (3, 13, 0),
        (3, 13, usize::from(u16::MAX) + 1),
        (usize::BITS as u8, 63, 1),
    ] {
        assert!(MainTraceMaskGroupV1::empty_v1(native, common, width).is_err());
    }
    for (range, uncertain) in [(0..0, false), (0..9, false), (1..2, false), (0..1, true)] {
        let events = RefCell::new(Vec::new());
        let mut rng = OrderedEntropy {
            draws: 0,
            events: &events,
            fail: None,
            unwind: false,
        };
        let mut group = MainTraceMaskGroupV1::empty_v1(3, 13, 8).unwrap();
        assert!(
            group
                .sample_and_replay_batch_with_v1(
                    range,
                    MainBoundedTransformPolicyV1::for_test_v1(8, 8),
                    &mut rng,
                    |_| panic!("invalid admission cannot touch source"),
                    |_, _, _| panic!("invalid admission cannot dispatch"),
                    || uncertain
                )
                .is_err()
        );
        assert_eq!(rng.draws, 0);
    }
    let mut rng = StdRng::from_seed([5; 32]);
    let mut before = rng.clone();
    for noncanonical in [false, true] {
        let mut group = MainTraceMaskGroupV1::empty_v1(3, 13, 1).unwrap();
        assert!(
            group
                .sample_and_replay_batch_with_v1(
                    0..1,
                    MainBoundedTransformPolicyV1::for_test_v1(8, 1),
                    &mut rng,
                    |_| {
                        let mut n = native(3, 0);
                        if noncanonical {
                            n[0] = F(u64::MAX);
                        } else {
                            n.0.reserve_exact(1);
                        }
                        Ok(n)
                    },
                    |_, _, _| panic!("bad native input cannot dispatch"),
                    || false
                )
                .is_err()
        );
    }
    assert_eq!(rng.next_u64(), before.next_u64());
}

#[test]
fn fused_joined_roots_frontiers_and_opened_rows_match_original_masks_across_groups() {
    use aggregate::joined_trace::{JoinedTraceColumnKindV1, JoinedTraceCommitmentPlanV1};
    let mut parameters = AggregateProofLayoutV1::for_full_profile_v1()
        .unwrap()
        .parameters_v1();
    parameters.minimum_trace_log2 = 5;
    parameters.maximum_trace_log2 = 9;
    parameters.terminal_log2 = 3;
    parameters.terminal_degree_bound = 7;
    let layout = aggregate::AggregateProofLayoutV1::new(
        parameters,
        vec![
            aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: 5,
                segment_instances: 1,
                base_width: 9,
                aux_width: 9,
            },
            aggregate::AggregateTraceGroupLayoutV1 {
                native_trace_log2: 9,
                segment_instances: 1,
                base_width: 3,
                aux_width: 3,
            },
        ],
    )
    .unwrap();
    let logs = [5, 9];
    let widths = [9, 3];
    for kind in [JoinedTraceColumnKindV1::Base, JoinedTraceColumnKindV1::Aux] {
        let plan = JoinedTraceCommitmentPlanV1::new_v1(parameters, &layout, kind).unwrap();
        let mut old_rng = StdRng::from_seed([211; 32]);
        let mut new_rng = old_rng.clone();
        let original = logs
            .into_iter()
            .zip(widths)
            .enumerate()
            .map(|(g, (log, width))| {
                MainTraceMaskGroupV1::sample_v1(
                    log,
                    layout.common_lde_log2(),
                    width,
                    &mut old_rng,
                    |column| Ok(native(log, g * 100 + column)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let evaluate = |columns: &[aggregate::ZeroizingFieldColumnV1], native, common| {
            columns.iter().map(|column| crate::privacy_engines::transparent_stark::masked_trace_coefficients_on_coset_v1(column, native, common)
                .map(aggregate::ZeroizingFieldColumnV1::from_vec_v1).map_err(|_| AggregateStarkErrorV1::InvalidLayout)).collect::<Result<Vec<_>, _>>()
        };
        let indices = [0, 1, (1_usize << layout.common_lde_log2()) - 1];
        let expected = plan
            .commit_replayed_v1(
                &AGGREGATE_DOMAINS_V1,
                &indices,
                |g, c| {
                    Ok(original[g]
                        .replay_v1(c, &native(logs[g], g * 100 + c))
                        .unwrap()
                        .into_vec_v1())
                },
                evaluate,
            )
            .unwrap();
        let mut groups = logs
            .into_iter()
            .zip(widths)
            .map(|(log, width)| {
                MainTraceMaskGroupV1::empty_v1(log, layout.common_lde_log2(), width).unwrap()
            })
            .collect::<Vec<_>>();
        let mut retained = logs
            .iter()
            .zip(widths)
            .enumerate()
            .map(|(group, (&log, width))| {
                super::super::main_retained_rfc::MainRetainedRfcV1::for_original_mask_test_v1(
                    group, width, log,
                )
            })
            .collect::<Vec<_>>();
        let mut pending = Vec::new().into_iter();
        let actual = plan
            .commit_replayed_v1(
                &AGGREGATE_DOMAINS_V1,
                &indices,
                |g, c| {
                    if pending.len() == 0 {
                        let end = widths[g].min(c + 8);
                        let mut batch = groups[g]
                            .sample_and_replay_batch_with_v1(
                                c..widths[g].min(c + 8),
                                MainBoundedTransformPolicyV1::for_test_v1(1 << logs[g], 4),
                                &mut new_rng,
                                |column| Ok(native(logs[g], g * 100 + column)),
                                cpu,
                                || false,
                            )
                            .unwrap();
                        retained[g].retain_batch_v1(g, c..end, &mut batch).unwrap();
                        pending = batch.into_iter();
                    }
                    Ok(pending.next().unwrap().into_vec_v1())
                },
                evaluate,
            )
            .unwrap();
        assert_eq!(actual.commitment.root, expected.commitment.root);
        assert_eq!(actual.commitment.frontier, expected.commitment.frontier);
        assert_eq!(actual.opened_rows, expected.opened_rows);
        assert_eq!(new_rng.next_u64(), old_rng.next_u64());
        let next_rng = new_rng.clone().next_u64();
        let replayed = plan
            .commit_replayed_v1(
                &AGGREGATE_DOMAINS_V1,
                &indices,
                |g, c| {
                    let mut column = retained[g].copy_columns_v1(g, c..c + 1).unwrap();
                    Ok(column.pop().unwrap().into_vec_v1())
                },
                evaluate,
            )
            .unwrap();
        assert_eq!(replayed.commitment.root, expected.commitment.root);
        assert_eq!(replayed.commitment.frontier, expected.commitment.frontier);
        assert_eq!(replayed.opened_rows, expected.opened_rows);
        assert_eq!(
            new_rng.next_u64(),
            next_rng,
            "cached replay never draws entropy"
        );
        let evaluate_retained = |columns: &[aggregate::ZeroizingFieldColumnV1],
                                 native,
                                 common,
                                 selected: Option<&[usize]>| {
            evaluate(columns, native, common).map(|full| {
                full.into_iter()
                    .map(|column| match selected {
                        Some(indices) => aggregate::ZeroizingFieldColumnV1::from_vec_v1(
                            indices.iter().map(|&row| column[row]).collect(),
                        ),
                        None => column,
                    })
                    .collect::<Vec<_>>()
            })
        };
        let (initial, cut) = plan
            .commit_retained_replayed_v1(
                &AGGREGATE_DOMAINS_V1,
                &[],
                None,
                |g, c| {
                    let mut columns = retained[g].copy_columns_v1(g, c..c + 1).unwrap();
                    Ok(columns.pop().unwrap().into_vec_v1())
                },
                evaluate_retained,
            )
            .unwrap();
        assert_eq!(initial.commitment.root, expected.commitment.root);
        assert!(initial.opened_rows.is_empty());
        assert!(initial.commitment.frontier.is_empty());
        let cut = cut.unwrap();
        cut.check_root_v1(1 << layout.common_lde_log2(), expected.commitment.root)
            .unwrap();
        let (selected, absent_cut) = plan
            .commit_retained_replayed_v1(
                &AGGREGATE_DOMAINS_V1,
                &indices,
                Some(&cut),
                |g, c| {
                    let mut columns = retained[g].copy_columns_v1(g, c..c + 1).unwrap();
                    Ok(columns.pop().unwrap().into_vec_v1())
                },
                evaluate_retained,
            )
            .unwrap();
        assert!(absent_cut.is_none());
        assert_eq!(selected.commitment.root, expected.commitment.root);
        assert_eq!(selected.commitment.frontier, expected.commitment.frontier);
        assert_eq!(selected.opened_rows, expected.opened_rows);
        let next_rng = new_rng.clone().next_u64();
        let mutated = plan.commit_retained_replayed_v1(
            &AGGREGATE_DOMAINS_V1,
            &indices,
            Some(&cut),
            |g, c| {
                let mut columns = retained[g].copy_columns_v1(g, c..c + 1).unwrap();
                let mut column = columns.pop().unwrap();
                if g == 0 && c == 0 {
                    let last = column.len() - 1;
                    column[last] = column[last].add(F::ONE);
                }
                Ok(column.into_vec_v1())
            },
            evaluate_retained,
        );
        assert!(
            mutated.is_err(),
            "the actual retained-root replay must reject a changed complete mask tail"
        );
        assert_eq!(
            new_rng.next_u64(),
            next_rng,
            "retained verification draws no entropy"
        );
    }
}

#[test]
#[ignore = "requires normal Metal privacy build; initial resident source and coefficient component parity only"]
fn fused_log19_width8_required_metal_preserves_cpu_coefficients_and_entropy() {
    let mut cpu_rng = StdRng::from_seed([212; 32]);
    let mut metal_rng = cpu_rng.clone();
    let mut cpu_group = MainTraceMaskGroupV1::empty_v1(19, 22, 8).unwrap();
    let mut metal_group = MainTraceMaskGroupV1::empty_v1(19, 22, 8).unwrap();
    let expected = cpu_group
        .sample_and_replay_batch_with_v1(
            0..8,
            MainBoundedTransformPolicyV1::cpu_v1(),
            &mut cpu_rng,
            |column| Ok(native(19, column)),
            |_, _, _| panic!("CPU admission cannot dispatch"),
            goldilocks_transform_completion_uncertain_v1,
        )
        .unwrap();
    let mut completed = 0;
    let actual = metal_group
        .sample_and_replay_batch_with_v1(
            0..8,
            MainBoundedTransformPolicyV1::for_test_v1(1 << 19, 8),
            &mut metal_rng,
            |column| Ok(native(19, column)),
            |words, root, direction| {
                assert_eq!(direction, Direction::Inverse);
                let backend = transform_goldilocks_columns_v1(
                    words,
                    root,
                    direction,
                    fastpq_prover::ExecutionMode::Gpu,
                )?;
                assert_eq!(backend, Backend::Metal);
                completed += words.len();
                Ok(backend)
            },
            goldilocks_transform_completion_uncertain_v1,
        )
        .unwrap();
    assert_eq!(completed, 8);
    assert_eq!(actual, expected);
    for (cpu, metal) in cpu_group.masks.iter().zip(&metal_group.masks) {
        assert_eq!(cpu.coefficients(), metal.coefficients());
    }
    assert_eq!(cpu_rng.next_u64(), metal_rng.next_u64());
}

#[test]
fn retained_original_source_poisoning_is_refused_before_entropy_or_cache_population() {
    for poison in [false, true] {
        let events = RefCell::new(Vec::new());
        let mut rng = OrderedEntropy {
            draws: 0,
            events: &events,
            fail: None,
            unwind: false,
        };
        let mut group = MainTraceMaskGroupV1::empty_v1(3, 13, 3).unwrap();
        let mut retained =
            super::super::main_retained_rfc::MainRetainedRfcV1::for_original_mask_test_v1(0, 3, 3);
        let output = group.sample_and_replay_batch_with_v1(
            0..3,
            MainBoundedTransformPolicyV1::cpu_v1(),
            &mut rng,
            |column| {
                assert_eq!(column, 0);
                let mut source = native(3, column);
                if poison {
                    source[0] = F(u64::MAX);
                } else {
                    source.0.pop();
                }
                Ok(source)
            },
            |_, _, _| panic!("poisoned source cannot transform"),
            || false,
        );
        assert_eq!(output, Err(ZkX509StarkErrorV1::ProfileMismatch));
        assert_eq!(rng.draws, 0);
        assert!(group.masks.is_empty());
        assert!(retained.copy_columns_v1(0, 0..1).is_err());
        // Retention is reached only after a successful original producer result.
        if let Ok(mut batch) = output {
            retained.retain_batch_v1(0, 0..3, &mut batch).unwrap();
            panic!("poisoned source cannot be retained");
        }
    }
}
