//! `ConvertToVOLE` for one small-VOLE instance (FAEST v3.0 section 6).
//!
//! Instance `i` has `N = 2^d` leaf seeds. Leaf `j` is expanded to the string
//! `r_j = PRG(sd_j, iv, i + 2^31; bits)` and the strings are folded level by level:
//! `v_c` is the sum of the entries at odd positions of level `c`, and the next
//! level holds the sums of neighbouring pairs. The last remaining entry is `u`.
//! Equivalently `u = sum_j r_j` and `v_c = sum_{j : bit c of j is 1} r_j`.
//!
//! The fold is done in one pass over the leaves with a stack of `d` partial sums,
//! so the working memory is `(d + 1) * ceil(bits / 8)` bytes whatever `N` is, and
//! no leaf string is kept.
//!
//! The verifier knows every seed but `sd_Delta`. It runs the same fold on the
//! reordered list `r'_0 = 0`, `r'_j = r_{j xor Delta}`, which yields
//! `q_c = v_c + Delta_c * u` ([`convert_to_vole_hidden`]).
//!
//! The order of operations depends on the leaf position and on the public hidden
//! index only. Seeds, strings and sums are secret on the prover's side; the
//! working buffers are erased on return.

use zeroize::Zeroizing;

use super::{Input, VoleError, bits::xor_into, check_length, product};
use crate::{
    bavc::BavcError,
    params::{IV_BYTES, VoleParams},
    prg::Prg,
};

/// Tweak of the generator of small-VOLE instance 0; instance `i` uses
/// `SMALL_VOLE_TWEAK + i`.
pub const SMALL_VOLE_TWEAK: u32 = 1 << 31;

/// The public sizes of one instance.
struct Instance {
    depth: usize,
    leaves: usize,
    lb: usize,
    width: usize,
    tweak: u32,
}

impl Instance {
    fn new(
        params: &VoleParams,
        instance: usize,
        seeds: usize,
        bits: usize,
        columns: usize,
    ) -> Result<Self, VoleError> {
        let out_of_range = VoleError::InstanceOutOfRange {
            instance,
            tau: params.tau(),
        };
        let depth = params.depth(instance).ok_or(out_of_range)?;
        let leaves = params.leaves_of(instance).ok_or(out_of_range)?;
        let offset = u32::try_from(instance).map_err(|_| out_of_range)?;
        let tweak = SMALL_VOLE_TWEAK.checked_add(offset).ok_or(out_of_range)?;
        let lb = params.lambda().bytes();
        let width = bits.div_ceil(8);
        check_length(Input::Seeds, product("leaf seeds", leaves, lb)?, seeds)?;
        check_length(
            Input::Columns,
            product("small-VOLE columns", depth, width)?,
            columns,
        )?;
        Ok(Self {
            depth,
            leaves,
            lb,
            width,
            tweak,
        })
    }

    /// Fold the leaves into `columns`; the last remaining entry is returned.
    ///
    /// With `hidden = Some(Delta)` the leaf at position 0 is zero and position
    /// `j >= 1` reads seed slot `j xor Delta`, so slot `Delta` is never read.
    fn fold(
        &self,
        iv: &[u8; IV_BYTES],
        seeds: &[u8],
        hidden: Option<usize>,
        bits: usize,
        columns: &mut [u8],
    ) -> Result<Zeroizing<Vec<u8>>, VoleError> {
        let width = self.width;
        columns.fill(0);
        let mut stack = Zeroizing::new(vec![0u8; self.depth * width]);
        let mut current = Zeroizing::new(vec![0u8; width]);
        for leaf in 0..self.leaves {
            if hidden.is_some() && leaf == 0 {
                current.fill(0);
            } else {
                let slot = leaf ^ hidden.unwrap_or(0);
                let seed = &seeds[slot * self.lb..(slot + 1) * self.lb];
                Prg::new(seed)?.fill_bits(iv, self.tweak, bits, &mut current)?;
            }
            // `current` is entry `leaf >> level` of level `level`. While that index
            // is odd it is added to the column of the level and merged with its
            // left neighbour, which waits on the stack.
            let mut level = 0;
            while (leaf >> level) & 1 == 1 {
                let range = level * width..(level + 1) * width;
                xor_into(&mut columns[range.clone()], &current);
                xor_into(&mut current, &stack[range]);
                level += 1;
            }
            if level < self.depth {
                stack[level * width..(level + 1) * width].copy_from_slice(&current);
            }
        }
        Ok(current)
    }
}

/// The prover's `ConvertToVOLE` for instance `instance`: from all `N_i` leaf seeds
/// to `u` and the `d_i` columns `v_0 || ... || v_{d_i - 1}`.
///
/// `seeds` is `sd_{i,0} || ... || sd_{i,N_i - 1}` (`lambda / 8` bytes each, as
/// [`crate::bavc::Commitment::seeds`] returns them). Every string has `bits` bits
/// in `ceil(bits / 8)` bytes with the unused high bits of the last byte zero.
/// Everything here is secret.
///
/// # Errors
/// * [`VoleError::InstanceOutOfRange`] unless `instance < tau`;
/// * [`VoleError::InvalidLength`] unless `seeds` is `N_i * lambda / 8` bytes, `u`
///   is `ceil(bits / 8)` bytes and `v` is `d_i * ceil(bits / 8)` bytes.
pub fn convert_to_vole(
    params: &VoleParams,
    instance: usize,
    iv: &[u8; IV_BYTES],
    seeds: &[u8],
    bits: usize,
    u: &mut [u8],
    v: &mut [u8],
) -> Result<(), VoleError> {
    let shape = Instance::new(params, instance, seeds.len(), bits, v.len())?;
    check_length(Input::SmallVoleU, shape.width, u.len())?;
    let last = shape.fold(iv, seeds, None, bits, v)?;
    u.copy_from_slice(&last);
    Ok(())
}

/// The verifier's `ConvertToVOLE` for instance `instance`: from the `N_i - 1`
/// revealed leaf seeds and the hidden index `Delta_i` to the `d_i` columns
/// `q_0 || ... || q_{d_i - 1}` with `q_c = v_c + Delta_{i,c} * u_i`.
///
/// `seeds` holds all `N_i` slots in index order, as
/// [`crate::bavc::Reconstruction::seeds`] returns them; slot `hidden` is never
/// read. Everything here is public.
///
/// # Errors
/// * [`VoleError::InstanceOutOfRange`] unless `instance < tau`;
/// * [`VoleError::InvalidLength`] unless `seeds` is `N_i * lambda / 8` bytes and `q`
///   is `d_i * ceil(bits / 8)` bytes;
/// * [`BavcError::IndexOutOfRange`] (wrapped) unless `hidden < N_i`.
pub fn convert_to_vole_hidden(
    params: &VoleParams,
    instance: usize,
    iv: &[u8; IV_BYTES],
    seeds: &[u8],
    hidden: u16,
    bits: usize,
    q: &mut [u8],
) -> Result<(), VoleError> {
    let shape = Instance::new(params, instance, seeds.len(), bits, q.len())?;
    let index = usize::from(hidden);
    if index >= shape.leaves {
        return Err(BavcError::IndexOutOfRange {
            vector: instance,
            index,
            leaves: shape.leaves,
        }
        .into());
    }
    shape.fold(iv, seeds, Some(index), bits, q)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        params::{FAEST_128F, FAEST_EM_192S, SecurityLevel},
        prg::prg,
    };

    const IV: [u8; 16] = [7; 16];

    fn seeds(params: &VoleParams, instance: usize) -> Vec<u8> {
        let len = params.leaves_of(instance).expect("instance") * params.lambda().bytes();
        (0..len)
            .map(|index| u8::try_from((index * 131 + instance * 17 + 5) % 256).expect("byte"))
            .collect()
    }

    /// The definition, level by level, on a list of strings.
    fn by_definition(mut list: Vec<Vec<u8>>, depth: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut columns = Vec::new();
        for _ in 0..depth {
            let mut column = vec![0u8; list[0].len()];
            let mut next = Vec::new();
            for pair in list.chunks(2) {
                for (slot, byte) in column.iter_mut().zip(&pair[1]) {
                    *slot ^= *byte;
                }
                next.push(pair[0].iter().zip(&pair[1]).map(|(a, b)| a ^ b).collect());
            }
            columns.push(column);
            list = next;
        }
        (list.remove(0), columns)
    }

    fn strings(params: &VoleParams, instance: usize, seeds: &[u8], bits: usize) -> Vec<Vec<u8>> {
        let tweak = SMALL_VOLE_TWEAK + u32::try_from(instance).expect("small");
        seeds
            .chunks(params.lambda().bytes())
            .map(|seed| {
                let mut out = vec![0u8; bits.div_ceil(8)];
                prg(seed, &IV, tweak, bits, &mut out).expect("valid call");
                out
            })
            .collect()
    }

    #[test]
    fn the_streamed_fold_is_the_level_by_level_definition() {
        for (params, bits) in [(*FAEST_128F.vole(), 173usize), (*FAEST_EM_192S.vole(), 64)] {
            for instance in [0, params.tau() - 1] {
                let depth = params.depth(instance).expect("instance");
                let width = bits.div_ceil(8);
                let seeds = seeds(&params, instance);
                let (want_u, want_v) =
                    by_definition(strings(&params, instance, &seeds, bits), depth);
                let mut u = vec![0xffu8; width];
                let mut v = vec![0xffu8; depth * width];
                convert_to_vole(&params, instance, &IV, &seeds, bits, &mut u, &mut v)
                    .expect("valid call");
                assert_eq!(u, want_u);
                assert_eq!(v, want_v.concat());
                // The unused bits of the last byte are zero.
                if !bits.is_multiple_of(8) {
                    let spare = 0xffu8 << (bits % 8);
                    assert_eq!(u[width - 1] & spare, 0);
                    assert!(v.chunks(width).all(|column| column[width - 1] & spare == 0));
                }
            }
        }
    }

    #[test]
    fn the_hidden_fold_is_the_prover_fold_shifted_by_the_index() {
        let params = *FAEST_128F.vole();
        let bits = 200;
        let width = bits / 8;
        for instance in [0, 5] {
            let depth = params.depth(instance).expect("instance");
            let leaves = params.leaves_of(instance).expect("instance");
            let seeds = seeds(&params, instance);
            let mut u = vec![0u8; width];
            let mut v = vec![0u8; depth * width];
            convert_to_vole(&params, instance, &IV, &seeds, bits, &mut u, &mut v)
                .expect("valid call");
            for hidden in [0, 1, leaves / 2 + 3, leaves - 1] {
                // The verifier's view: the hidden slot is unknown.
                let mut revealed = seeds.clone();
                let lb = params.lambda().bytes();
                revealed[hidden * lb..(hidden + 1) * lb].fill(0);
                let mut q = vec![0xffu8; depth * width];
                let index = u16::try_from(hidden).expect("index fits");
                convert_to_vole_hidden(&params, instance, &IV, &revealed, index, bits, &mut q)
                    .expect("valid call");
                for (level, (q_column, v_column)) in
                    q.chunks(width).zip(v.chunks(width)).enumerate()
                {
                    let mut want = v_column.to_vec();
                    if (hidden >> level) & 1 == 1 {
                        xor_into(&mut want, &u);
                    }
                    assert_eq!(q_column, want.as_slice(), "hidden {hidden} level {level}");
                }
            }
        }
    }

    #[test]
    fn malformed_calls_are_typed_errors() {
        let params = *FAEST_128F.vole();
        assert_eq!(params.lambda(), SecurityLevel::L128);
        let seeds = seeds(&params, 1);
        let depth = params.depth(1).expect("instance");
        let (mut u, mut v) = (vec![0u8; 4], vec![0u8; depth * 4]);
        assert_eq!(
            convert_to_vole(&params, 17, &IV, &seeds, 32, &mut u, &mut v),
            Err(VoleError::InstanceOutOfRange {
                instance: 17,
                tau: 17
            })
        );
        assert_eq!(
            convert_to_vole(&params, 1, &IV, &seeds[1..], 32, &mut u, &mut v),
            Err(VoleError::InvalidLength {
                input: Input::Seeds,
                expected: seeds.len(),
                actual: seeds.len() - 1
            })
        );
        assert_eq!(
            convert_to_vole(&params, 1, &IV, &seeds, 33, &mut u, &mut v),
            Err(VoleError::InvalidLength {
                input: Input::Columns,
                expected: depth * 5,
                actual: depth * 4
            })
        );
        assert_eq!(
            convert_to_vole(&params, 1, &IV, &seeds, 32, &mut u[..3], &mut v),
            Err(VoleError::InvalidLength {
                input: Input::SmallVoleU,
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            convert_to_vole_hidden(&params, 1, &IV, &seeds, 128, 32, &mut v),
            Err(VoleError::Bavc(BavcError::IndexOutOfRange {
                vector: 1,
                index: 128,
                leaves: 128
            }))
        );
        assert_eq!(
            convert_to_vole_hidden(&params, 1, &IV, &seeds, 0, 32, &mut v[1..]),
            Err(VoleError::InvalidLength {
                input: Input::Columns,
                expected: depth * 4,
                actual: depth * 4 - 1
            })
        );
        // Zero bits is a valid, empty conversion.
        assert_eq!(
            convert_to_vole(&params, 1, &IV, &seeds, 0, &mut [], &mut []),
            Ok(())
        );
    }
}
