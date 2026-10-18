//! Original coefficient replay, bounded ownership and failure-path tests.

use super::super::super::private_table::inspection;
use super::*;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn native_v1() -> Vec<Vec<F>> {
    (0..ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1)
        .map(|column| {
            (0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
                .map(|row| F((3 + column * 11 + row * 7) as u64))
                .collect()
        })
        .collect()
}
fn evaluate_v1(coefficients: &[F], point: F) -> F {
    coefficients
        .iter()
        .rev()
        .fold(F::ZERO, |value, coefficient| {
            value.mul(point).add(*coefficient)
        })
}

#[test]
fn retained_ca_coefficients_preserve_native_values_and_replay_the_same_mask() {
    let owner = CaOriginalMaskedColumnsV1::sample_v1(
        CaColumnFamilyV1::Auxiliary,
        native_v1(),
        &mut StdRng::seed_from_u64(73),
    )
    .unwrap();
    assert_eq!(owner.family_v1(), CaColumnFamilyV1::Auxiliary);
    assert_eq!(CaColumnFamilyV1::Base.width_v1(), 695);
    assert_eq!(CaColumnFamilyV1::Auxiliary.width_v1(), 128);
    let n = ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1;
    let coefficients = n + CA_MASK_DEGREE_V1 + 1;
    assert_eq!(
        owner.allocated_payload_bytes_v1().unwrap(),
        128 * (core::mem::size_of::<Vec<F>>() + coefficients * 8)
    );
    assert_eq!(
        owner.allocated_payload_bytes_v1().unwrap(),
        CaOriginalMaskedColumnsV1::payload_bound_v1(CaColumnFamilyV1::Auxiliary).unwrap()
    );
    assert_eq!(
        CaOriginalMaskedColumnsV1::payload_bound_v1(CaColumnFamilyV1::Base).unwrap(),
        695 * (core::mem::size_of::<Vec<F>>() + coefficients * core::mem::size_of::<F>())
    );
    assert!(format!("{owner:?}").contains("<redacted>"));
    let root = goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1).unwrap();
    for column in [0, 96, 116, 120, 124, 127] {
        let values = owner.column_v1(column).unwrap();
        assert_eq!(values.len(), coefficients);
        for row in [0, 1, 12, 13, 103, n - 1] {
            assert_eq!(
                evaluate_v1(values, root.pow(row as u128)),
                F((3 + column * 11 + row * 7) as u64)
            );
        }
    }
    let original = owner.column_v1(116).unwrap().to_vec();
    let first = owner.column_lde_v1(116).unwrap();
    let second = owner.column_lde_v1(116).unwrap();
    assert_eq!(&*first, &*second);
    assert_eq!(owner.column_v1(116).unwrap(), original);
    let lde_root = goldilocks_primitive_root_v1(ZK_X509_CA_FRI_LDE_LOG2_V1).unwrap();
    for row in [0, 1, 17, 65535] {
        assert_eq!(
            first[row],
            evaluate_v1(
                &original,
                F(GOLDILOCKS_GENERATOR_V1).mul(lde_root.pow(row as u128))
            )
        );
    }
    let z = E::canonical([13, 17, 19, 23]).unwrap();
    let expected = original.iter().rev().fold(E::ZERO, |value, coefficient| {
        value.mul(z).add(E::from_base(*coefficient))
    });
    assert_eq!(owner.open_v1(116, z).unwrap(), expected);
    assert!(owner.open_v1(128, z).is_err());
    assert!(owner.column_v1(128).is_err());
    assert!(owner.column_lde_v1(128).is_err());
    assert!(owner.open_v1(0, E::ZERO).is_err());
    assert!(owner.open_v1(0, E::ONE).is_err());
    let local = owner.local_lde_v1().unwrap();
    assert_eq!(local.len(), 128);
    assert_eq!(local[116], *first);
    assert!(local.iter().all(|column| column.len() == 65_536));
    drop(local);
    let ((), observations) = inspection::observe_v1(|| drop(owner));
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.cells == coefficients)
            .count(),
        128
    );
    // This is public fixture data. Production replay never creates this copy.
}

#[derive(Debug)]
struct EntropyFailure;
impl core::fmt::Display for EntropyFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("held CA test entropy failure")
    }
}
struct PartialEntropy {
    remaining: usize,
    unwind: bool,
}
impl TryRngCore for PartialEntropy {
    type Error = EntropyFailure;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.try_next_u64().map(|v| v as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        if self.remaining == 0 {
            if self.unwind {
                panic!("deliberate CA coefficient entropy unwind");
            }
            return Err(EntropyFailure);
        }
        self.remaining -= 1;
        Ok(7 + self.remaining as u64)
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for block in destination.chunks_mut(8) {
            let value = self.try_next_u64()?.to_le_bytes();
            block.copy_from_slice(&value[..block.len()]);
        }
        Ok(())
    }
}

#[test]
fn retained_ca_coefficients_clear_native_and_completed_columns_on_error_and_unwind() {
    for unwind in [false, true] {
        let (result, observations) = inspection::observe_v1(|| {
            catch_unwind(AssertUnwindSafe(|| {
                CaOriginalMaskedColumnsV1::sample_v1(
                    CaColumnFamilyV1::Auxiliary,
                    native_v1(),
                    &mut PartialEntropy {
                        remaining: CA_MASK_DEGREE_V1 + 4,
                        unwind,
                    },
                )
            }))
        });
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(_))));
        }
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
        assert!(
            observations
                .iter()
                .filter(|item| item.cells == ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
                .count()
                >= 128
        );
        assert!(observations.iter().any(|item| item.cells
            == ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 + CA_MASK_DEGREE_V1 + 1
            && item.nonzero_before > 0));
    }
}

#[test]
fn malformed_native_ca_input_is_cleared_before_any_entropy_is_read() {
    for variant in 0..3 {
        let mut native = native_v1();
        match variant {
            0 => {
                native.pop();
            }
            1 => {
                native[0].pop();
            }
            _ => native[0][0] = F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1),
        }
        let (result, observations) = inspection::observe_v1(|| {
            CaOriginalMaskedColumnsV1::sample_v1(
                CaColumnFamilyV1::Auxiliary,
                native,
                &mut PartialEntropy {
                    remaining: 0,
                    unwind: true,
                },
            )
        });
        assert!(result.is_err());
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
}
