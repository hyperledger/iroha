//! GPU helpers for scheduler access-set bucketing.
//!
//! These utilities attempt to offload the `(key, tx_index, rw_flag)` sorting
//! step to CUDA when the build enables it and a device is available. They fall
//! back to deterministic CPU ordering otherwise so callers can rely on the
//! same output regardless of hardware.
#[cfg(feature = "cuda")]
use std::convert::TryFrom;
/// Error reported when GPU sorting cannot be completed.
#[derive(Copy, Clone, Debug)]
pub enum GpuSortError {
    /// The slice length exceeds the supported limit (`u32::MAX` elements).
    LengthOverflow,
    /// One of the transaction indices does not fit in `u32`.
    TxIndexOverflow,
    /// CUDA support is not compiled in or no device is available.
    Unsupported,
    /// The CUDA kernel launched but returned an error.
    LaunchFailed,
}
/// Triplet `(key, tx_index, rw_flag)` encoded for GPU sorting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessTriplet {
    /// Interned access key identifier.
    pub key: u32,
    /// Index of the transaction owning the access.
    pub tx_index: usize,
    /// Read (`0`) or write (`1`) flag for the access.
    pub flag: u8,
}
/// Attempt to sort triplets using the CUDA bitonic path.
///
/// Returns `Ok(())` when the GPU produced a sorted ordering, or a [`GpuSortError`] describing the
/// fallback reason. Callers should fall back to CPU ordering when an error is returned.
///
/// # Errors
///
/// Returns [`GpuSortError::LengthOverflow`] when the slice length exceeds
/// `u32::MAX`, [`GpuSortError::TxIndexOverflow`] when a transaction index does
/// not fit in `u32`, and [`GpuSortError::Unsupported`] or
/// [`GpuSortError::LaunchFailed`] when the GPU path is unavailable.
pub fn sort_triplets_gpu(triplets: &mut [AccessTriplet]) -> Result<(), GpuSortError> {
    if triplets.len() > (u32::MAX as usize) {
        return Err(GpuSortError::LengthOverflow);
    }
    #[cfg(feature = "cuda")]
    {
        if !ivm::cuda_available() {
            return Err(GpuSortError::Unsupported);
        }
        // Prepare high/low words preserving stability: high word stores
        // (key << 32) | tx_index, low word stores (flag << 32) | position.
        let mut hi = Vec::with_capacity(triplets.len());
        let mut lo = Vec::with_capacity(triplets.len());
        for (pos, triplet) in triplets.iter().enumerate() {
            let tx_idx_u32 =
                u32::try_from(triplet.tx_index).map_err(|_| GpuSortError::TxIndexOverflow)?;
            let hi_word = ((triplet.key as u64) << 32) | (tx_idx_u32 as u64);
            let lo_word = ((triplet.flag as u64) << 32) | (pos as u64);
            hi.push(hi_word);
            lo.push(lo_word);
        }
        match ivm::bitonic_sort_pairs(&mut hi, &mut lo) {
            Some(()) => {
                for (out, (hi_word, lo_word)) in triplets.iter_mut().zip(hi.into_iter().zip(lo)) {
                    out.key = (hi_word >> 32) as u32;
                    out.tx_index = (hi_word & 0xFFFF_FFFF) as u32 as usize;
                    out.flag = lo_word.to_le_bytes()[4];
                }
                Ok(())
            }
            None => Err(GpuSortError::LaunchFailed),
        }
    }
    #[cfg(not(feature = "cuda"))]
    {
        let _ = triplets;
        Err(GpuSortError::Unsupported)
    }
}
/// Sort triplets in place using the GPU when available, otherwise fall back to
/// the deterministic CPU ordering. Returns `true` when the GPU path succeeded.
pub fn sort_triplets_gpu_or_cpu(triplets: &mut [AccessTriplet]) -> bool {
    if matches!(sort_triplets_gpu(triplets), Ok(())) {
        true
    } else {
        triplets.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.tx_index.cmp(&b.tx_index))
                .then_with(|| a.flag.cmp(&b.flag))
        });
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_fallback_matches_reference_order() {
        let mut triplets = vec![
            AccessTriplet {
                key: 5,
                tx_index: 2,
                flag: 1,
            },
            AccessTriplet {
                key: 5,
                tx_index: 1,
                flag: 0,
            },
            AccessTriplet {
                key: 3,
                tx_index: 3,
                flag: 0,
            },
            AccessTriplet {
                key: 3,
                tx_index: 3,
                flag: 1,
            },
        ];
        // Force CPU by running on a clone and comparing to manual ordering.
        let mut reference = triplets.clone();
        reference.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.tx_index.cmp(&b.tx_index))
                .then_with(|| a.flag.cmp(&b.flag))
        });
        let used_gpu = sort_triplets_gpu_or_cpu(&mut triplets);
        // Regardless of backend availability, the ordering must match the reference.
        assert_eq!(
            triplets
                .iter()
                .map(|t| (t.key, t.tx_index, t.flag))
                .collect::<Vec<_>>(),
            reference
                .iter()
                .map(|t| (t.key, t.tx_index, t.flag))
                .collect::<Vec<_>>()
        );
        if used_gpu {
            // If the GPU path succeeded we still expect the lexicographic order.
            assert_eq!(triplets.first().unwrap().key, 3);
        }
    }
    #[test]
    fn gpu_sort_failure_preserves_adversarial_inputs_for_cpu_retry() {
        let mut triplets = vec![
            AccessTriplet {
                key: u32::MAX,
                tx_index: usize::MAX,
                flag: u8::MAX,
            },
            AccessTriplet {
                key: 0,
                tx_index: 0,
                flag: 1,
            },
            AccessTriplet {
                key: u32::MAX,
                tx_index: u32::MAX as usize,
                flag: 0,
            },
        ];
        let original = triplets.clone();
        assert!(
            sort_triplets_gpu(&mut triplets).is_err(),
            "direct GPU sort should reject unsupported or unencodable adversarial inputs"
        );
        assert_eq!(
            triplets, original,
            "failed GPU sort must leave caller input intact for deterministic CPU retry"
        );
    }
    #[test]
    fn gpu_or_cpu_sort_orders_extreme_values_after_gpu_rejection() {
        let mut triplets = vec![
            AccessTriplet {
                key: u32::MAX,
                tx_index: usize::MAX,
                flag: u8::MAX,
            },
            AccessTriplet {
                key: 42,
                tx_index: 7,
                flag: 1,
            },
            AccessTriplet {
                key: 0,
                tx_index: usize::MAX,
                flag: 0,
            },
            AccessTriplet {
                key: 42,
                tx_index: 7,
                flag: 0,
            },
            AccessTriplet {
                key: u32::MAX,
                tx_index: u32::MAX as usize,
                flag: u8::MAX - 1,
            },
        ];
        let mut reference = triplets.clone();
        reference.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.tx_index.cmp(&b.tx_index))
                .then_with(|| a.flag.cmp(&b.flag))
        });
        let used_gpu = sort_triplets_gpu_or_cpu(&mut triplets);
        assert!(
            !used_gpu,
            "usize::MAX transaction indices must force CPU fallback instead of truncated CUDA keys"
        );
        assert_eq!(triplets, reference);
    }
}
