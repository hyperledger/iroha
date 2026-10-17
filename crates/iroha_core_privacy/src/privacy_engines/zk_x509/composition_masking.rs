//! Private adjacent-chunk masks for the canonical X509 quotient decomposition.
//!
//! With stride s and independent `T_i` of degree below h, replace `Q_i` by
//! `Q_i` + X^s `T_i` - T_{i-1}. The recomposed quotient is unchanged, while each
//! chunk stays below the original FRI cap D by choosing s = D - h. Here h is
//! the number of FRI queries plus the one extension-field DEEP query.
//! TODO: complete the joint mixed-native-domain transcript hiding argument,
//! including adaptive openings, full FRI terminals, and construction failures.

use crate::privacy_engines::aggregate_stark::{
    AggregateProofLayoutV1, AggregateStarkErrorV1 as Error, AggregateStarkParametersV1,
};

/// Public decomposition geometry, derived from the fixed subproof profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct QuotientChunkGeometryV1 {
    cap: usize,
    stride: usize,
    masks: usize,
    chunks: usize,
}

impl QuotientChunkGeometryV1 {
    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        parameters: AggregateStarkParametersV1,
    ) -> Result<Self, Error> {
        layout.validate(parameters)?;
        Self::from_dimensions_v1(
            layout.fri_degree_cap(parameters)?,
            parameters.composition_degree_chunks,
            parameters.query_count,
        )
    }

    fn from_dimensions_v1(cap: usize, chunks: usize, queries: usize) -> Result<Self, Error> {
        let masks = queries.checked_add(1).ok_or(Error::InvalidLayout)?;
        let stride = cap
            .checked_sub(masks)
            .filter(|s| *s >= masks)
            .ok_or(Error::InvalidLayout)?;
        if chunks < 2 || queries == 0 || stride.checked_mul(chunks).is_none() {
            return Err(Error::InvalidLayout);
        }
        Ok(Self {
            cap,
            stride,
            masks,
            chunks,
        })
    }

    pub(super) const fn stride_v1(self) -> usize {
        self.stride
    }

    /// Charge the only additional live mask owner; full chunks are charged by
    /// the existing D-coefficient chunk reservation. No mask matrix is retained.
    pub(super) const fn mask_scratch_bytes_v1() -> usize {
        core::mem::size_of::<crate::privacy_engines::transparent_stark::GoldilocksFp4V1>()
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
mod prover {
    use super::super::private_table::{PrivateTableV1, zeroize_words_v1};
    use super::*;
    use crate::privacy_engines::{
        aggregate_stark::map_transparent_error_v1,
        transparent_stark::{
            GOLDILOCKS_GENERATOR_V1, GoldilocksFieldV1 as F, GoldilocksFp4V1 as E,
            goldilocks_fp4_evaluate_coset_v1, goldilocks_fp4_ifft_v1, goldilocks_primitive_root_v1,
            random_goldilocks_fp4_v1,
        },
    };
    use rand::TryRngCore;

    fn erase_fields(values: &mut [E]) {
        zeroize_words_v1(values);
    }
    fn erase_chunks(values: &mut [Vec<E>]) {
        for row in values {
            erase_fields(row);
        }
    }
    struct Mask(E);
    impl Drop for Mask {
        fn drop(&mut self) {
            erase_fields(core::slice::from_mut(&mut self.0));
        }
    }

    impl QuotientChunkGeometryV1 {
        /// Split all nonzero coefficients without truncation, reserving the full
        /// admitted chunk capacity before any private coefficient is inserted.
        pub(crate) fn split_v1(self, coefficients: &[E]) -> Result<Vec<Vec<E>>, Error> {
            let covered = self
                .stride
                .checked_mul(self.chunks)
                .ok_or(Error::InvalidLayout)?;
            if coefficients.iter().any(|value| !value.is_canonical()) {
                return Err(Error::NonCanonicalField);
            }
            if coefficients
                .get(covered..)
                .is_some_and(|tail| tail.iter().any(|v| *v != E::ZERO))
            {
                return Err(Error::FriDegree);
            }
            let mut chunks = PrivateTableV1::new(Vec::new(), erase_chunks);
            chunks
                .try_reserve_exact(self.chunks)
                .map_err(|_| Error::AllocationFailure)?;
            for index in 0..self.chunks {
                let mut chunk = PrivateTableV1::new(Vec::new(), erase_fields);
                chunk
                    .try_reserve_exact(self.cap)
                    .map_err(|_| Error::AllocationFailure)?;
                let start = index.checked_mul(self.stride).ok_or(Error::InvalidLayout)?;
                let end = start
                    .checked_add(self.stride)
                    .ok_or(Error::InvalidLayout)?
                    .min(coefficients.len());
                if start < end {
                    // Keep the public slice geometry even when private high
                    // coefficients vanish. Trimming by value exposes their
                    // position through scan work and the last chunk's length.
                    chunk.extend_from_slice(&coefficients[start..end]);
                }
                chunks.push(chunk.into_vec());
            }
            Ok(chunks.into_vec())
        }

        /// Add independently sampled masks before any composition commitment.
        /// The caller owns every chunk in a clearing guard across this operation:
        /// entropy failure can leave a partial private result, which must be dropped.
        pub(crate) fn blind_v1<R: TryRngCore>(
            self,
            chunks: &mut [Vec<E>],
            rng: &mut R,
        ) -> Result<(), Error> {
            if chunks.len() != self.chunks
                || chunks.iter().any(|chunk| {
                    chunk.len() > self.stride
                        || chunk.capacity() < self.cap
                        || chunk.iter().any(|value| !value.is_canonical())
                })
            {
                return Err(Error::InvalidLayout);
            }
            // Every reservation precedes private writes. Resizing cannot allocate.
            for (index, chunk) in chunks.iter_mut().enumerate() {
                let len = if index + 1 < self.chunks {
                    self.cap
                } else {
                    chunk.len().max(self.masks)
                };
                chunk.resize(len, E::ZERO);
            }
            for index in 0..self.chunks - 1 {
                for offset in 0..self.masks {
                    let mask =
                        Mask(random_goldilocks_fp4_v1(rng).map_err(map_transparent_error_v1)?);
                    chunks[index][self.stride + offset] =
                        chunks[index][self.stride + offset].add(mask.0);
                    chunks[index + 1][offset] = chunks[index + 1][offset].sub(mask.0);
                }
            }
            Ok(())
        }

        /// Consume one quotient codeword and return independently blinded chunk
        /// codewords, clearing all intermediate private owners on every exit.
        pub(crate) fn split_evaluations_v1<R: TryRngCore>(
            self,
            evaluations: Vec<E>,
            log: u8,
            rng: &mut R,
        ) -> Result<Vec<Vec<E>>, Error> {
            // Adopt the original private allocation before any fallible check.
            let mut coefficients = PrivateTableV1::new(evaluations, erase_fields);
            let rows = 1usize
                .checked_shl(u32::from(log))
                .ok_or(Error::InvalidLayout)?;
            if coefficients.len() != rows || coefficients.iter().any(|v| !v.is_canonical()) {
                return Err(Error::InvalidLayout);
            }
            let root = goldilocks_primitive_root_v1(log).map_err(map_transparent_error_v1)?;
            goldilocks_fp4_ifft_v1(&mut coefficients, root).map_err(map_transparent_error_v1)?;
            let shift = F(GOLDILOCKS_GENERATOR_V1)
                .inv()
                .ok_or(Error::InvalidLayout)?;
            let mut power = F::ONE;
            for coefficient in &mut *coefficients {
                *coefficient = coefficient.mul_base(power);
                power = power.mul(shift);
            }
            let mut chunks = PrivateTableV1::new(self.split_v1(&coefficients)?, erase_chunks);
            drop(coefficients);
            self.blind_v1(&mut chunks, rng)?;
            let mut output = PrivateTableV1::new(Vec::new(), erase_chunks);
            output
                .try_reserve_exact(self.chunks)
                .map_err(|_| Error::AllocationFailure)?;
            for chunk in &*chunks {
                output.push(
                    goldilocks_fp4_evaluate_coset_v1(chunk, rows, root, F(GOLDILOCKS_GENERATOR_V1))
                        .map_err(map_transparent_error_v1)?,
                );
            }
            Ok(output.into_vec())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::privacy_engines::zk_x509::private_table::inspection;
        use rand::{RngCore, SeedableRng, rngs::StdRng};

        fn value(index: usize) -> E {
            E::canonical([index as u64 + 1, index as u64 + 3, 5, 7]).unwrap()
        }
        fn evaluate(coefficients: &[E], point: E) -> E {
            coefficients
                .iter()
                .rev()
                .fold(E::ZERO, |sum, coefficient| sum.mul(point).add(*coefficient))
        }
        // Independent coefficient convolution: no polynomial evaluator or FFT
        // shared with the constructor participates in this cancellation check.
        fn recompose(chunks: &[Vec<E>], stride: usize) -> Vec<E> {
            let mut result =
                vec![E::ZERO; chunks.len() * stride + chunks.iter().map(Vec::len).max().unwrap()];
            for (index, chunk) in chunks.iter().enumerate() {
                for (degree, coefficient) in chunk.iter().enumerate() {
                    result[index * stride + degree] =
                        result[index * stride + degree].add(*coefficient);
                }
            }
            result
        }

        #[test]
        fn fixed_profile_strides_preserve_degree_caps_and_quotient_capacity() {
            for (cap, chunks, stride, maximum) in
                [(589_824, 6, 589_687, 3_158_433), (9_216, 4, 9_079, 34_851)]
            {
                let geometry =
                    QuotientChunkGeometryV1::from_dimensions_v1(cap, chunks, 136).unwrap();
                assert_eq!(geometry.stride_v1(), stride);
                assert_eq!(geometry.masks, 137);
                assert_eq!(stride + geometry.masks, cap);
                assert!(maximum < stride * chunks);
            }
            for (cap, chunks, queries) in [
                (0, 4, 136),
                (137, 4, 136),
                (273, 4, 136),
                (9216, 1, 136),
                (9216, 4, 0),
                (9216, 4, usize::MAX),
                (usize::MAX, 4, 136),
            ] {
                assert!(QuotientChunkGeometryV1::from_dimensions_v1(cap, chunks, queries).is_err());
            }
            assert_eq!(QuotientChunkGeometryV1::mask_scratch_bytes_v1(), 32);
        }

        #[test]
        fn adjacent_masks_cancel_in_every_coefficient_with_distinct_private_randomness() {
            let geometry = QuotientChunkGeometryV1::from_dimensions_v1(16, 4, 3).unwrap();
            for nonzero in [false, true] {
                let coefficients: Vec<_> = (0..geometry.stride * geometry.chunks)
                    .map(|index| if nonzero { value(index) } else { E::ZERO })
                    .collect();
                let mut first =
                    PrivateTableV1::new(geometry.split_v1(&coefficients).unwrap(), erase_chunks);
                let mut second =
                    PrivateTableV1::new(geometry.split_v1(&coefficients).unwrap(), erase_chunks);
                let pointers: Vec<_> = first.iter().map(Vec::as_ptr).collect();
                geometry
                    .blind_v1(&mut first, &mut StdRng::from_seed([17; 32]))
                    .unwrap();
                geometry
                    .blind_v1(&mut second, &mut StdRng::from_seed([19; 32]))
                    .unwrap();
                assert_ne!(*first, *second);
                assert_eq!(first.iter().map(Vec::as_ptr).collect::<Vec<_>>(), pointers);
                for chunks in [&*first, &*second] {
                    assert!(chunks.iter().all(|chunk| chunk.len() <= geometry.cap));
                    let actual = recompose(chunks, geometry.stride);
                    assert_eq!(&actual[..coefficients.len()], coefficients.as_slice());
                    assert!(actual[coefficients.len()..].iter().all(|v| *v == E::ZERO));
                    for point in [E::ZERO, E::ONE, value(53)] {
                        let direct =
                            chunks
                                .iter()
                                .enumerate()
                                .fold(E::ZERO, |sum, (index, chunk)| {
                                    sum.add(
                                        evaluate(chunk, point)
                                            .mul(point.pow((index * geometry.stride) as u128)),
                                    )
                                });
                        assert_eq!(direct, evaluate(&coefficients, point));
                    }
                }
            }
        }

        #[test]
        fn canonical_split_keeps_last_admitted_coefficient_and_refuses_hidden_tail() {
            let geometry = QuotientChunkGeometryV1::from_dimensions_v1(16, 4, 3).unwrap();
            let mut coefficients = vec![E::ZERO; geometry.stride * geometry.chunks + 3];
            coefficients[geometry.stride * geometry.chunks - 1] = value(7);
            let chunks = geometry.split_v1(&coefficients).unwrap();
            assert_eq!(chunks.last().unwrap().len(), geometry.stride);
            assert_eq!(chunks.last().unwrap().last(), Some(&value(7)));
            coefficients[geometry.stride * geometry.chunks] = E::ONE;
            assert_eq!(geometry.split_v1(&coefficients), Err(Error::FriDegree));
            coefficients[geometry.stride * geometry.chunks] = E::ZERO;
            assert_eq!(
                geometry
                    .split_v1(&[])
                    .unwrap()
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>(),
                0
            );
            assert!(geometry.split_v1(&coefficients).is_ok());
        }

        #[test]
        fn private_coefficient_values_do_not_change_chunk_geometry_or_mask_consumption() {
            let geometry = QuotientChunkGeometryV1::from_dimensions_v1(16, 4, 3).unwrap();
            for length in [0, 1, geometry.stride + 1, geometry.stride * geometry.chunks] {
                let zero = vec![E::ZERO; length];
                let dense: Vec<_> = (0..length).map(value).collect();
                let mut sparse = vec![E::ZERO; length];
                if let Some(first) = sparse.first_mut() {
                    *first = value(11);
                }
                let mut expected = None;
                for coefficients in [&zero, &sparse, &dense] {
                    let mut chunks =
                        PrivateTableV1::new(geometry.split_v1(coefficients).unwrap(), erase_chunks);
                    let before: Vec<_> = chunks.iter().map(|v| (v.len(), v.capacity())).collect();
                    let mut rng = StdRng::from_seed([43; 32]);
                    geometry.blind_v1(&mut chunks, &mut rng).unwrap();
                    let after: Vec<_> = chunks.iter().map(|v| (v.len(), v.capacity())).collect();
                    let observed = (before, after, rng.next_u64());
                    if let Some(expected) = &expected {
                        assert_eq!(&observed, expected);
                    } else {
                        expected = Some(observed);
                    }
                    let actual = recompose(&chunks, geometry.stride);
                    assert_eq!(&actual[..length], coefficients.as_slice());
                    assert!(actual[length..].iter().all(|v| *v == E::ZERO));
                }
            }
        }

        #[test]
        fn invalid_chunk_owners_are_rejected_before_entropy_or_private_mutation() {
            let geometry = QuotientChunkGeometryV1::from_dimensions_v1(16, 4, 3).unwrap();
            for malformed in 0..3 {
                let mut chunks = geometry.split_v1(&[value(7)]).unwrap();
                match malformed {
                    0 => {
                        chunks.pop();
                    }
                    1 => {
                        chunks[3].resize(geometry.stride + 1, E::ONE);
                    }
                    _ => {
                        chunks[3] = Vec::new();
                    }
                }
                let expected = chunks.clone();
                let mut rng = StdRng::from_seed([23; 32]);
                let mut untouched = rng.clone();
                assert_eq!(
                    geometry.blind_v1(&mut chunks, &mut rng),
                    Err(Error::InvalidLayout)
                );
                assert_eq!(chunks, expected);
                assert_eq!(rng.next_u64(), untouched.next_u64());
            }
        }

        struct PartialEntropy {
            draws: usize,
            unwind: bool,
        }
        impl TryRngCore for PartialEntropy {
            type Error = std::io::Error;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                unreachable!("byte sampler")
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                unreachable!("byte sampler")
            }
            fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
                assert_eq!(destination.len(), 8);
                if self.draws == 6 {
                    destination.fill(0x5a);
                    assert!(!self.unwind, "injected entropy unwind");
                    return Err(std::io::Error::other("injected entropy failure"));
                }
                destination.copy_from_slice(&(17 + self.draws as u64).to_le_bytes());
                self.draws += 1;
                Ok(())
            }
        }

        #[test]
        fn private_owners_clear_after_success_partial_entropy_failure_and_unwind() {
            let geometry = QuotientChunkGeometryV1::from_dimensions_v1(16, 4, 3).unwrap();
            for failure in [None, Some(false), Some(true)] {
                let (outcome, observations) = inspection::observe_v1(|| {
                    std::panic::catch_unwind(|| {
                        let mut chunks = PrivateTableV1::new(
                            geometry.split_v1(&[value(11)]).unwrap(),
                            erase_chunks,
                        );
                        match failure {
                            None => {
                                geometry.blind_v1(&mut chunks, &mut StdRng::from_seed([31; 32]))
                            }
                            Some(unwind) => geometry
                                .blind_v1(&mut chunks, &mut PartialEntropy { draws: 0, unwind }),
                        }
                    })
                });
                match failure {
                    None => assert!(outcome.unwrap().is_ok()),
                    Some(false) => assert!(outcome.unwrap().is_err()),
                    Some(true) => assert!(outcome.is_err()),
                }
                let expected_masks = if failure.is_none() {
                    (geometry.chunks - 1) * geometry.masks
                } else {
                    1
                };
                assert_eq!(
                    observations.iter().map(|row| row.cells).sum::<usize>(),
                    (geometry.chunks - 1) * geometry.cap + geometry.masks + expected_masks
                );
                assert!(observations.iter().any(|row| row.nonzero_before > 0));
                assert!(observations.iter().all(|row| row.nonzero_after == 0));
            }
        }

        #[test]
        fn coset_split_recomposes_at_all_rows_and_rejects_forbidden_degree() {
            let geometry = QuotientChunkGeometryV1::from_dimensions_v1(16, 4, 3).unwrap();
            let root = goldilocks_primitive_root_v1(6).unwrap();
            let shift = F(GOLDILOCKS_GENERATOR_V1);
            let coefficients: Vec<_> = (0..48).map(value).collect();
            let original: Vec<_> = (0..64)
                .map(|index| evaluate(&coefficients, E::from_base(shift.mul(root.pow(index)))))
                .collect();
            let chunks = geometry
                .split_evaluations_v1(original.clone(), 6, &mut StdRng::from_seed([37; 32]))
                .unwrap();
            for (row, expected) in original.iter().enumerate() {
                let point = E::from_base(shift.mul(root.pow(row as u128)));
                let actual = chunks
                    .iter()
                    .enumerate()
                    .fold(E::ZERO, |sum, (index, chunk)| {
                        sum.add(chunk[row].mul(point.pow((index * geometry.stride) as u128)))
                    });
                assert_eq!(actual, *expected);
            }
            let forbidden: Vec<_> = (0..64)
                .map(|index| E::from_base(shift.mul(root.pow(index))).pow(48))
                .collect();
            assert_eq!(
                geometry.split_evaluations_v1(forbidden, 6, &mut StdRng::from_seed([41; 32])),
                Err(Error::FriDegree)
            );
            let (result, observations) = inspection::observe_v1(|| {
                geometry.split_evaluations_v1(
                    vec![value(7); 63],
                    6,
                    &mut StdRng::from_seed([43; 32]),
                )
            });
            assert_eq!(result, Err(Error::InvalidLayout));
            assert_eq!(observations.iter().map(|row| row.cells).sum::<usize>(), 63);
            assert!(observations.iter().all(|row| row.nonzero_after == 0));
        }
    }
}
