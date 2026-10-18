//! Bounded clearing replay of one temporal lookup auxiliary column.

use super::{
    F, ZkX509Rfc5280StarkChallengesV1, ZkX509Rfc5280StarkErrorV1, numeric, zeroize_fields_v1,
};

#[cfg(test)]
use super::{PrivateTableV1, ZK_X509_RFC5280_STARK_TRACE_SIZE_V1, zero_safe_inverse_v1};

struct ClearingEventV1(numeric::NumericLookupEventV1<F>);
impl Drop for ClearingEventV1 {
    fn drop(&mut self) {
        self.0.source.zeroize_v1();
        self.0.query.zeroize_v1();
        self.0.multiplicity.zeroize_v1();
        zeroize_fields_v1(&mut self.0.tuple);
    }
}

/// Advance one numeric lookup lane, returning all four prefix/inverse values.
/// The caller retains and clears the two sums, and checks both after the final row.
#[cfg(test)]
pub(super) fn step_v1(
    event: numeric::NumericLookupEventV1<F>,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    lane: usize,
    state: &mut [F; 2],
) -> Result<[F; 4], ZkX509Rfc5280StarkErrorV1> {
    step_with_inverse_v1(event, challenges, lane, state, &mut zero_safe_inverse_v1)
}

/// Shared recurrence; alternate inverse ownership is test-only until qualified.
pub(super) fn step_with_inverse_v1(
    event: numeric::NumericLookupEventV1<F>,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    lane: usize,
    state: &mut [F; 2],
    inverse: &mut impl FnMut(F, F) -> (F, F),
) -> Result<[F; 4], ZkX509Rfc5280StarkErrorV1> {
    let event = ClearingEventV1(event);
    let event = &event.0;
    if lane >= numeric::LOOKUP_LANES_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    if ![event.source, event.query, event.multiplicity]
        .into_iter()
        .chain(event.tuple)
        .all(|value| F::canonical(value.0).is_some())
        || !matches!(event.source, F::ZERO | F::ONE)
        || !matches!(event.query, F::ZERO | F::ONE)
        || event.source == F::ONE && event.query == F::ONE
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    let active = event.source.add(event.query);
    let factor = numeric::lookup_factor_v1(event.tuple, challenges.tuple[lane]);
    let (zero, inverse) = inverse(active, factor);
    let values = [inverse, zero, state[0], state[1]];
    let weight = event.source.mul(event.multiplicity).sub(event.query);
    state[0] = state[0].add(weight.mul(inverse));
    state[1] = state[1].add(weight.mul(zero));
    Ok(values)
}

#[cfg(test)]
struct ClearingSumsV1([F; 2]);
#[cfg(test)]
impl Drop for ClearingSumsV1 {
    fn drop(&mut self) {
        zeroize_fields_v1(&mut self.0);
    }
}

/// Emit a prefix column without retaining another event or column matrix.
#[cfg(test)]
pub(super) fn build_column_v1(
    rows: usize,
    offset: usize,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
    mut event_at: impl FnMut(
        usize,
    ) -> Result<numeric::NumericLookupEventV1<F>, ZkX509Rfc5280StarkErrorV1>,
) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
    challenges.validate()?;
    if rows == 0
        || rows > ZK_X509_RFC5280_STARK_TRACE_SIZE_V1
        || offset >= numeric::LOOKUP_AUX_WIDTH_V1
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let kind = offset / numeric::LOOKUP_LANES_V1;
    let lane = offset % numeric::LOOKUP_LANES_V1;
    let mut values = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
    values
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut sums = ClearingSumsV1([F::ZERO; 2]);
    for index in 0..rows {
        let event = event_at(index)?;
        let mut output = step_v1(event, challenges, lane, &mut sums.0)?;
        values.push(output[kind]);
        zeroize_fields_v1(&mut output);
    }
    // The final row is included: the AIR terminal checks prefix + final delta.
    // This also catches a malformed census while replaying inverse/zero columns.
    if sums.0 != [F::ZERO; 2] {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(values.into_vec())
}

#[cfg(test)]
mod tests {
    use super::super::super::private_table::inspection;
    use super::*;

    fn challenges() -> ZkX509Rfc5280StarkChallengesV1 {
        ZkX509Rfc5280StarkChallengesV1 {
            tuple: core::array::from_fn(|lane| {
                core::array::from_fn(|column| F(7 + (lane * 12 + column) as u64))
            }),
        }
    }

    #[test]
    fn borrowed_challenge_refusal_precedes_geometry_and_event_replay() {
        let valid = challenges();
        let mut invalid = valid;
        invalid.tuple[0][0] = F::ZERO;
        let before = invalid;
        let calls = std::cell::Cell::new(0_usize);
        let mut event_at = |_| {
            calls.set(calls.get() + 1);
            Ok(event(true, 23, 1))
        };
        assert_eq!(
            build_column_v1(0, 0, &invalid, &mut event_at),
            Err(ZkX509Rfc5280StarkErrorV1::Challenge)
        );
        assert_eq!(
            build_column_v1(0, 0, &valid, &mut event_at),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(invalid, before);
        assert_eq!(valid.validate(), Ok(()));
    }

    fn event(source: bool, value: u64, multiplicity: u64) -> numeric::NumericLookupEventV1<F> {
        let mut tuple = [F::ZERO; 12];
        tuple[0] = F(value);
        numeric::NumericLookupEventV1 {
            source: F(u64::from(source)),
            query: F(u64::from(!source)),
            multiplicity: F(multiplicity),
            tuple,
        }
    }

    fn row(columns: &[PrivateTableV1<F>], index: usize) -> numeric::NumericLookupRowV1<F> {
        numeric::NumericLookupRowV1 {
            inverse: core::array::from_fn(|lane| columns[lane][index]),
            zero: core::array::from_fn(|lane| columns[4 + lane][index]),
            sum: core::array::from_fn(|lane| columns[8 + lane][index]),
            zero_sum: core::array::from_fn(|lane| columns[12 + lane][index]),
        }
    }

    #[test]
    fn temporal_lookup_columns_match_all_air_rows_and_include_last_row() {
        for singular_lane in [None, Some(0), Some(1), Some(2), Some(3)] {
            let value = singular_lane.map_or(23, |lane| {
                F::ZERO.sub(challenges().tuple[lane][0].inv().unwrap()).0
            });
            let values = [(true, value, 2), (false, value, 0), (false, value, 0)];
            let columns = (0..numeric::LOOKUP_AUX_WIDTH_V1)
                .map(|offset| {
                    PrivateTableV1::new(
                        build_column_v1(values.len(), offset, &challenges(), |index| {
                            let (source, value, multiplicity) = values[index];
                            Ok(event(source, value, multiplicity))
                        })
                        .unwrap(),
                        zeroize_fields_v1,
                    )
                })
                .collect::<Vec<_>>();
            for index in 0..values.len() {
                let (source, value, multiplicity) = values[index];
                let current = row(&columns, index);
                let next = row(&columns, (index + 1) % values.len());
                let residues = numeric::lookup_residues_v1(
                    &event(source, value, multiplicity),
                    &current,
                    &next,
                    F(u64::from(index == 0)),
                    F(u64::from(index + 1 != values.len())),
                    F(u64::from(index + 1 == values.len())),
                    &challenges().tuple,
                );
                assert!(residues.iter().all(|value| *value == F::ZERO));
            }
            for lane in 0..4 {
                let factor = F::ONE.add(F(value).mul(challenges().tuple[lane][0]));
                let singular = factor == F::ZERO;
                assert_eq!(singular, singular_lane == Some(lane));
                let expected_inverse = if singular {
                    F::ZERO
                } else {
                    factor.inv().unwrap()
                };
                assert_eq!(columns[lane].as_slice(), &[expected_inverse; 3]);
                assert_eq!(columns[4 + lane].as_slice(), &[F(u64::from(singular)); 3]);
                assert_eq!(
                    columns[8 + lane].as_slice(),
                    &[F::ZERO, expected_inverse.mul(F(2)), expected_inverse]
                );
                assert_eq!(
                    columns[12 + lane].as_slice(),
                    &[F::ZERO, F(2 * u64::from(singular)), F(u64::from(singular))]
                );
            }
        }
    }

    #[test]
    fn temporal_lookup_replay_rejects_unbalanced_census_and_invalid_event_before_publication() {
        for offset in 0..numeric::LOOKUP_AUX_WIDTH_V1 {
            let singular = F::ZERO
                .sub(
                    challenges().tuple[offset % numeric::LOOKUP_LANES_V1][0]
                        .inv()
                        .unwrap(),
                )
                .0;
            for value in [0, 23, singular] {
                // Missing a query must fail even for inverse/zero columns.
                assert!(
                    build_column_v1(2, offset, &challenges(), |index| {
                        Ok(event(index == 0, value, 2))
                    })
                    .is_err()
                );
            }
            assert!(
                build_column_v1(2, offset, &challenges(), |index| {
                    Ok(event(index == 0, 23 + index as u64, 1))
                })
                .is_err()
            );
        }
        for field in 0..4 {
            assert!(
                build_column_v1(1, 0, &challenges(), |_| {
                    let mut invalid = event(true, 1, 1);
                    match field {
                        0 => invalid.source = F(2),
                        1 => invalid.query = F::ONE,
                        2 => invalid.multiplicity = F(u64::MAX),
                        _ => invalid.tuple[5] = F(u64::MAX),
                    }
                    Ok(invalid)
                })
                .is_err()
            );
        }
        for (rows, offset) in [
            (0, 0),
            (ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 + 1, 0),
            (1, 16),
        ] {
            assert!(
                build_column_v1(rows, offset, &challenges(), |_| panic!(
                    "shape must fail before callback"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn temporal_lookup_replay_clears_actual_cells_on_late_error_unwind_and_success_transfer() {
        for unwind in [false, true] {
            let (result, observations) = inspection::observe_v1(|| {
                std::panic::catch_unwind(|| {
                    build_column_v1(3, 0, &challenges(), |index| {
                        if index == 2 {
                            assert!(!unwind, "synthetic late replay unwind");
                            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
                        }
                        Ok(event(index == 0, 23, 1))
                    })
                })
            });
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert!(
                observations
                    .iter()
                    .any(|record| record.cells == 2 && record.nonzero_before == 2)
            );
            assert!(observations.iter().all(|record| record.nonzero_after == 0));
        }
        let ((), observations) = inspection::observe_v1(|| {
            let output = PrivateTableV1::new(
                build_column_v1(2, 0, &challenges(), |index| Ok(event(index == 0, 23, 1))).unwrap(),
                zeroize_fields_v1,
            );
            assert!(output.iter().all(|value| *value != F::ZERO));
            drop(output);
        });
        assert!(
            observations
                .iter()
                .any(|record| record.cells == 2 && record.nonzero_before == 2)
        );
        assert!(observations.iter().all(|record| record.nonzero_after == 0));
    }
}
