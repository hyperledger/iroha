//! Small-set utilities used in the pipeline for compact u32 key sets.
//!
//! Provides deterministic helpers for sorting, deduplicating, and intersecting small u32 sets. A
//! scalar baseline is always available; when the crate feature `simd` is enabled the helpers
//! transparently switch to stable fixed-width kernels that are suitable for compiler
//! auto-vectorization and produce identical results.
use core::cmp::Ordering;
/// Sort a slice of `u32` and compact it in-place by removing duplicates. Returns the number of
/// unique elements; the first `len` items are the deduplicated, sorted values.
#[inline]
pub fn sort_dedup_u32_in_place(slice: &mut [u32]) -> usize {
    #[cfg(feature = "simd")]
    if let Some(len) = simd::sort_dedup_u32(slice) {
        return len;
    }
    scalar::sort_dedup_u32(slice)
}
/// Intersect two sorted `u32` slices and return the intersection (deduplicated).
#[inline]
pub fn intersect_sorted_u32(a: &[u32], b: &[u32]) -> Vec<u32> {
    #[cfg(feature = "simd")]
    if let Some(out) = simd::intersect_sorted_u32(a, b) {
        return out;
    }
    scalar::intersect_sorted_u32(a, b)
}
mod scalar {
    use super::Ordering;
    #[inline]
    pub(super) fn sort_dedup_u32(slice: &mut [u32]) -> usize {
        if slice.len() <= 1 {
            return slice.len();
        }
        slice.sort_unstable();
        let mut write = 1usize;
        let mut last = slice[0];
        for i in 1..slice.len() {
            let v = slice[i];
            if v != last {
                slice[write] = v;
                write += 1;
                last = v;
            }
        }
        write
    }
    #[inline]
    pub(super) fn intersect_sorted_u32(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut j = 0usize;
        let mut last: Option<u32> = None;
        while i < a.len() && j < b.len() {
            let va = a[i];
            let vb = b[j];
            match va.cmp(&vb) {
                Ordering::Equal => {
                    if last != Some(va) {
                        out.push(va);
                        last = Some(va);
                    }
                    i += 1;
                    j += 1;
                }
                Ordering::Less => i += 1,
                Ordering::Greater => j += 1,
            }
        }
        out
    }
}
#[cfg(feature = "simd")]
mod simd {
    use super::scalar;

    const LANES: usize = 8;

    #[inline]
    pub(super) fn sort_dedup_u32(slice: &mut [u32]) -> Option<usize> {
        if slice.len() <= 1 {
            return Some(slice.len());
        }
        if slice.len() > LANES {
            return None;
        }
        bitonic_sort_small(slice);
        let new_len = compact_sorted(slice);
        Some(new_len)
    }

    #[inline]
    pub(super) fn intersect_sorted_u32(a: &[u32], b: &[u32]) -> Option<Vec<u32>> {
        if a.is_empty() || b.is_empty() {
            return Some(Vec::new());
        }
        let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
        if small.len() < LANES {
            return None;
        }
        let mut result = Vec::new();
        let mut last: Option<u32> = None;
        let mut idx_small = 0usize;
        let mut idx_large = 0usize;
        while idx_small + LANES <= small.len() && idx_large < large.len() {
            let chunk = &small[idx_small..idx_small + LANES];
            let min = chunk[0];
            let max = chunk[LANES - 1];
            while idx_large < large.len() && large[idx_large] < min {
                idx_large += 1;
            }
            let mut probe = idx_large;
            while probe < large.len() && large[probe] <= max {
                let value = large[probe];
                if chunk.contains(&value) && last != Some(value) {
                    result.push(value);
                    last = Some(value);
                }
                probe += 1;
            }
            if probe > idx_large {
                idx_large = probe;
            }
            idx_small += LANES;
        }
        if idx_small < small.len() && idx_large < large.len() {
            let tail = scalar::intersect_sorted_u32(&small[idx_small..], &large[idx_large..]);
            for value in tail {
                if last != Some(value) {
                    result.push(value);
                    last = Some(value);
                }
            }
        }
        Some(result)
    }

    #[inline]
    fn bitonic_sort_small(slice: &mut [u32]) {
        let len = slice.len();
        let mut buf = [u32::MAX; LANES];
        buf[..len].copy_from_slice(slice);

        // A fixed eight-lane bitonic network avoids unstable `portable_simd`
        // while retaining a branch-bounded kernel that LLVM can vectorize.
        let mut width = 2usize;
        while width <= LANES {
            let mut stride = width / 2;
            while stride > 0 {
                for left in 0..LANES {
                    let right = left ^ stride;
                    if right > left {
                        let ascending = left & width == 0;
                        let lhs = buf[left];
                        let rhs = buf[right];
                        if (ascending && lhs > rhs) || (!ascending && lhs < rhs) {
                            buf.swap(left, right);
                        }
                    }
                }
                stride /= 2;
            }
            width *= 2;
        }

        slice.copy_from_slice(&buf[..len]);
    }

    #[inline]
    fn compact_sorted(slice: &mut [u32]) -> usize {
        if slice.is_empty() {
            return 0;
        }
        let mut write = 1usize;
        let mut prev = slice[0];
        for idx in 1..slice.len() {
            let value = slice[idx];
            if value != prev {
                slice[write] = value;
                write += 1;
                prev = value;
            }
        }
        write
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sort_dedup_basic() {
        let mut v = vec![3, 1, 2, 2, 1, 4, 3];
        let n = sort_dedup_u32_in_place(&mut v);
        v.truncate(n);
        assert_eq!(v, vec![1, 2, 3, 4]);
    }
    #[test]
    fn sort_dedup_already_sorted() {
        let mut v = vec![1, 2, 3, 3, 4, 4];
        let n = sort_dedup_u32_in_place(&mut v);
        v.truncate(n);
        assert_eq!(v, vec![1, 2, 3, 4]);
    }
    #[test]
    fn intersect_sorted() {
        let a = vec![1, 2, 3, 5, 7, 9];
        let b = vec![2, 3, 4, 9, 10];
        let c = intersect_sorted_u32(&a, &b);
        assert_eq!(c, vec![2, 3, 9]);
    }
    #[cfg(feature = "simd")]
    #[test]
    fn simd_sort_matches_scalar_variants() {
        use super::scalar;
        let mut cases = [
            vec![5, 4, 3, 2, 1, 0, 0, 1],
            vec![1, 1, 1, 1, 1],
            vec![7, 2, 7, 3],
            vec![8, 7, 6, 5, 4, 3, 2, 1],
        ];
        for case in cases.iter_mut() {
            let mut scalar_vec = case.clone();
            let scalar_len = scalar::sort_dedup_u32(&mut scalar_vec);
            scalar_vec.truncate(scalar_len);
            let mut simd_vec = case.clone();
            let simd_len = super::simd::sort_dedup_u32(&mut simd_vec)
                .expect("SIMD path should handle <= 8 items");
            simd_vec.truncate(simd_len);
            assert_eq!(simd_vec, scalar_vec);
        }
    }
    #[cfg(feature = "simd")]
    #[test]
    fn simd_intersect_matches_scalar() {
        use super::scalar;
        let a = vec![1, 2, 2, 3, 5, 7, 9, 11];
        let b = vec![0, 2, 3, 4, 9, 11, 12, 13];
        let scalar_out = scalar::intersect_sorted_u32(&a, &b);
        let simd_out = super::simd::intersect_sorted_u32(&a, &b)
            .expect("SIMD path should activate for eight-element chunk");
        assert_eq!(simd_out, scalar_out);
    }
}
