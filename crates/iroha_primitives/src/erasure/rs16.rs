//! Reed-Solomon (16-bit) parity helpers shared across Torii and tooling.
//!
//! Symbols are little-endian GF(2^16) elements modulo x^16 + x^12 + x^3 + x + 1. Systematic
//! parity rows are `V[k..k+m] * V[..k]^-1` for the Vandermonde matrix `V[r][c] = (2^r)^c`;
//! one generator implementation serves the compact consensus codec and the owned-row API.
//! Row arithmetic runs on the host's SIMD backend or the scalar fallback with bit-identical
//! results.
#[path = "rs16/compact.rs"]
pub mod compact;
#[path = "rs16/kernel.rs"]
mod kernel;
#[cfg(test)]
#[path = "rs16/reference.rs"]
mod reference;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
const FIELD_ORDER: usize = 1 << 16;
const FIELD_MASK: u32 = 0x1_0000;
const FIELD_POLY: u32 = 0x1_100B; // x^16 + x^12 + x^3 + x + 1
const ORDER_MINUS_ONE: usize = FIELD_ORDER - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Scalar,
    #[cfg(all(
        feature = "simd-accel",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    Avx2,
    #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
    Neon,
}
/// Error returned when RS16 parity encoding fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rs16Error;
struct FieldTables {
    exp: Vec<u16>,
    log: Vec<u16>,
}
static SIMD_ENABLED: AtomicBool = AtomicBool::new(true);
/// Enable or disable SIMD acceleration for RS16 parity encoding.
pub fn set_simd_enabled(enabled: bool) {
    SIMD_ENABLED.store(enabled, Ordering::SeqCst);
}
/// Returns true when RS16 SIMD acceleration is enabled.
pub fn simd_enabled() -> bool {
    SIMD_ENABLED.load(Ordering::SeqCst)
}
fn tables() -> &'static FieldTables {
    static TABLES: OnceLock<FieldTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = vec![0u16; ORDER_MINUS_ONE * 2];
        let mut log = vec![0u16; FIELD_ORDER];
        let mut value: u32 = 1;
        for (idx, slot) in exp.iter_mut().take(ORDER_MINUS_ONE).enumerate() {
            let value_u16 = u16::try_from(value).expect("rs16 field element out of range");
            let idx_u16 = u16::try_from(idx).expect("rs16 log index out of range");
            *slot = value_u16;
            log[usize::from(value_u16)] = idx_u16;
            value <<= 1;
            if (value & FIELD_MASK) != 0 {
                value ^= FIELD_POLY;
            }
            value &= FIELD_MASK - 1;
        }
        let (lower, upper) = exp.split_at_mut(ORDER_MINUS_ONE);
        upper.copy_from_slice(lower);
        FieldTables { exp, log }
    })
}
/// Field product for matrix construction; row kernels use per-coefficient product tables.
#[inline]
fn gf_mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let tables = tables();
    let log_a = tables.log[a as usize] as usize;
    let log_b = tables.log[b as usize] as usize;
    tables.exp[log_a + log_b]
}
#[inline]
fn gf_inv(value: u16) -> Option<u16> {
    if value == 0 {
        return None;
    }
    let tables = tables();
    let log_v = tables.log[value as usize] as usize;
    Some(tables.exp[ORDER_MINUS_ONE - log_v])
}
#[inline]
fn gf_pow(exp: usize) -> u16 {
    let tables = tables();
    tables.exp[exp % ORDER_MINUS_ONE]
}
/// Gauss-Jordan inverse of the row-major `k x k` matrix, which is consumed as scratch.
fn invert(k: usize, matrix: &mut [u16], inverse: &mut [u16]) -> Result<(), Rs16Error> {
    inverse.fill(0);
    for row in 0..k {
        inverse[row * k + row] = 1;
    }
    for column in 0..k {
        let pivot = (column..k)
            .find(|row| matrix[row * k + column] != 0)
            .ok_or(Rs16Error)?;
        for index in 0..k {
            matrix.swap(column * k + index, pivot * k + index);
            inverse.swap(column * k + index, pivot * k + index);
        }
        let reciprocal = gf_inv(matrix[column * k + column]).ok_or(Rs16Error)?;
        for index in 0..k {
            matrix[column * k + index] = gf_mul(matrix[column * k + index], reciprocal);
            inverse[column * k + index] = gf_mul(inverse[column * k + index], reciprocal);
        }
        for row in 0..k {
            if row == column {
                continue;
            }
            let factor = matrix[row * k + column];
            for index in 0..k {
                matrix[row * k + index] ^= gf_mul(factor, matrix[column * k + index]);
                inverse[row * k + index] ^= gf_mul(factor, inverse[column * k + index]);
            }
        }
    }
    Ok(())
}
/// The sole generator construction: row-major `m x k` systematic parity coefficients in
/// `parity`, using `matrix` and `inverse` (`k x k` each) as scratch.
fn prepare(
    k: usize,
    m: usize,
    matrix: &mut [u16],
    inverse: &mut [u16],
    parity: &mut [u16],
) -> Result<(), Rs16Error> {
    for row in 0..k {
        for column in 0..k {
            matrix[row * k + column] = if row == 0 || column == 0 {
                1
            } else {
                gf_pow(row * column)
            };
        }
    }
    invert(k, matrix, inverse)?;
    for row in 0..m {
        for column in 0..k {
            let mut value = 0;
            for source in 0..k {
                let coefficient = if source == 0 {
                    1
                } else {
                    gf_pow((k + row) * source)
                };
                value ^= gf_mul(coefficient, inverse[source * k + column]);
            }
            parity[row * k + column] = value;
        }
    }
    Ok(())
}
type ParityCache = OnceLock<Mutex<HashMap<(usize, usize), Arc<[u16]>>>>;
/// Memoized [`prepare`] output for the owned-row API, whose Torii column stripes can have
/// thousands of data rows; the compact codec prepares into its caller-owned workspace.
fn parity_coefficients(data_shards: usize, parity_shards: usize) -> Result<Arc<[u16]>, Rs16Error> {
    static CACHE: ParityCache = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(data_shards, parity_shards))
        .cloned();
    if let Some(entry) = cached {
        return Ok(entry);
    }
    data_shards
        .checked_add(parity_shards)
        .filter(|total| data_shards != 0 && parity_shards != 0 && *total <= ORDER_MINUS_ONE)
        .ok_or(Rs16Error)?;
    let mut matrix = vec![0u16; data_shards * data_shards];
    let mut inverse = vec![0u16; data_shards * data_shards];
    let mut parity = vec![0u16; data_shards * parity_shards];
    prepare(
        data_shards,
        parity_shards,
        &mut matrix,
        &mut inverse,
        &mut parity,
    )?;
    let parity: Arc<[u16]> = parity.into();
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((data_shards, parity_shards), parity.clone());
    Ok(parity)
}
/// Every backend this host can run, scalar first, regardless of the global SIMD toggle.
#[cfg(test)]
fn host_backends() -> Vec<Backend> {
    let accelerated: Option<Backend> = None;
    #[cfg(all(
        feature = "simd-accel",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    let accelerated = accelerated
        .or_else(|| std::arch::is_x86_feature_detected!("avx2").then_some(Backend::Avx2));
    #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
    let accelerated = accelerated
        .or_else(|| std::arch::is_aarch64_feature_detected!("neon").then_some(Backend::Neon));
    std::iter::once(Backend::Scalar)
        .chain(accelerated)
        .collect()
}
fn choose_backend() -> Backend {
    if !simd_enabled() {
        return Backend::Scalar;
    }
    #[cfg(all(
        feature = "simd-accel",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    if std::arch::is_x86_feature_detected!("avx2") {
        return Backend::Avx2;
    }
    #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        return Backend::Neon;
    }
    Backend::Scalar
}
/// Encode RS16 parity for the provided data symbols and parity shard count.
///
/// # Errors
/// Returns `Rs16Error` if the data symbol rows are not the same length or the
/// parity matrix cannot be constructed.
pub fn encode_parity(
    data_symbols: &[Vec<u16>],
    parity_count: usize,
) -> Result<Vec<Vec<u16>>, Rs16Error> {
    encode_parity_with_backend(data_symbols, parity_count, choose_backend())
}
/// Convert chunk bytes into RS16 symbols padded to the requested symbol count.
pub fn symbols_from_chunk(symbol_count: usize, chunk: &[u8]) -> Vec<u16> {
    let mut symbols = vec![0u16; symbol_count];
    for (slot, pair) in symbols.iter_mut().zip(chunk.chunks(2)) {
        *slot = u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
    }
    symbols
}
/// Compute the parity chunk offset for a given stripe/parity index.
pub fn parity_offset(
    total_size: u64,
    stripe_index: usize,
    parity_index: usize,
    parity_shards: usize,
    chunk_size: u32,
) -> Option<u64> {
    let stride = u64::from(chunk_size);
    let slot = u64::try_from(stripe_index)
        .ok()?
        .checked_mul(parity_shards as u64)?
        .checked_add(parity_index as u64)?;
    total_size.checked_add(slot.checked_mul(stride)?)
}
/// Owned-row parity: data rows are staged as little-endian bytes one kernel group at a time,
/// so the transient copy is bounded by [`kernel::GROUP`] rows on every host byte order.
fn encode_parity_with_backend(
    data_symbols: &[Vec<u16>],
    parity_count: usize,
    backend: Backend,
) -> Result<Vec<Vec<u16>>, Rs16Error> {
    if data_symbols.is_empty() || parity_count == 0 {
        return Ok(Vec::new());
    }
    let symbol_count = data_symbols[0].len();
    if data_symbols.iter().any(|row| row.len() != symbol_count) {
        return Err(Rs16Error);
    }
    let data_count = data_symbols.len();
    let coefficients = parity_coefficients(data_count, parity_count)?;
    if symbol_count == 0 {
        return Ok(vec![Vec::new(); parity_count]);
    }
    let row_bytes = 2 * symbol_count;
    let mut parity = vec![0u8; parity_count.checked_mul(row_bytes).ok_or(Rs16Error)?];
    let mut staged = vec![0u8; data_count.min(kernel::GROUP) * row_bytes];
    for (group, rows) in data_symbols.chunks(kernel::GROUP).enumerate() {
        for (bytes, row) in staged.chunks_exact_mut(row_bytes).zip(rows) {
            for (pair, symbol) in bytes.chunks_exact_mut(2).zip(row) {
                pair.copy_from_slice(&symbol.to_le_bytes());
            }
        }
        let first = group * kernel::GROUP;
        for (coefficients, output) in coefficients
            .chunks_exact(data_count)
            .zip(parity.chunks_exact_mut(row_bytes))
        {
            kernel::combine(
                coefficients[first..first + rows.len()]
                    .iter()
                    .copied()
                    .zip(staged.chunks_exact(row_bytes)),
                output,
                group != 0,
                backend,
            );
        }
    }
    Ok(parity
        .chunks_exact(row_bytes)
        .map(|row| {
            row.chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        })
        .collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample_symbols(rows: usize, symbols: usize) -> Vec<Vec<u16>> {
        let mut data = Vec::with_capacity(rows);
        for row in 0..rows {
            let mut symbols_row = Vec::with_capacity(symbols);
            for idx in 0..symbols {
                let row_u16 = u16::try_from(row).expect("row index fits in u16");
                let idx_u16 = u16::try_from(idx).expect("symbol index fits in u16");
                symbols_row.push((row_u16 << 8) ^ idx_u16);
            }
            data.push(symbols_row);
        }
        data
    }
    #[test]
    fn parity_shape_is_stable() {
        let data = sample_symbols(4, 64);
        let parity = encode_parity(&data, 3).expect("parity");
        assert_eq!(parity.len(), 3);
        assert!(parity.iter().all(|row| row.len() == 64));
    }
    #[test]
    fn simd_toggle_roundtrip() {
        let prev = simd_enabled();
        set_simd_enabled(!prev);
        assert_eq!(simd_enabled(), !prev);
        assert_eq!(
            choose_backend() == Backend::Scalar,
            prev || host_backends().len() == 1
        );
        set_simd_enabled(prev);
    }
    #[test]
    fn simd_backends_match_scalar() {
        let data = sample_symbols(6, 128);
        let scalar = encode_parity_with_backend(&data, 4, Backend::Scalar).expect("scalar");
        for backend in host_backends() {
            let parity = encode_parity_with_backend(&data, 4, backend).expect("parity");
            assert_eq!(scalar, parity, "{backend:?}");
        }
    }
    /// The matrix field operations agree with the independent bit-serial reference.
    #[test]
    fn matrix_field_operations_match_reference() {
        let mut state = 0x9E37_79B9_u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            u16::try_from(state & 0xFFFF).expect("masked")
        };
        for _ in 0..20_000 {
            let (a, b) = (next(), next());
            assert_eq!(gf_mul(a, b), reference::mul(a, b), "{a:#x}*{b:#x}");
            if a != 0 {
                assert_eq!(gf_inv(a), Some(reference::inv(a)), "{a:#x}^-1");
            }
        }
        assert_eq!(gf_inv(0), None);
        for exponent in [0usize, 1, 15, 16, 65_534, 65_535, 65_536, 1 << 20] {
            assert_eq!(
                gf_pow(exponent),
                reference::pow(2, exponent as u64),
                "2^{exponent}"
            );
        }
    }
    /// The single generator construction matches the reference Vandermonde construction.
    #[test]
    fn generator_matches_reference_parity_matrix() {
        for (k, m) in [(1, 1), (1, 16), (4, 2), (16, 1), (16, 16), (7, 9), (40, 3)] {
            let coefficients = parity_coefficients(k, m).expect("coefficients");
            let expected = reference::parity_matrix(k, m)
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            assert_eq!(&*coefficients, expected.as_slice(), "{k}+{m}");
            assert!(Arc::ptr_eq(
                &coefficients,
                &parity_coefficients(k, m).expect("cached")
            ));
        }
        let mut singular = vec![1, 1, 1, 1];
        let mut inverse = vec![0; 4];
        assert_eq!(invert(2, &mut singular, &mut inverse), Err(Rs16Error));
    }
    /// `(data rows, parity rows, symbols per row, BLAKE3 of the little-endian parity rows)`
    /// pinned from the original kernels for the owned-row API used by Torii and `SoraFS`.
    #[rustfmt::skip]
    const PINNED_PARITY: &[(usize, usize, usize, &str)] = &[
        (1, 1, 1, "bf0de6eda1ae618676cbad90affb1fcac1519b9f7cd67c805e5d3e2cda4bdf5a"),
        (1, 3, 7, "78d414f0ad34af6c767e1283676a99384735432b8f6657885086d794592677dc"),
        (2, 2, 0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
        (4, 2, 8, "9011f8c4a0b247c3fc76935adc33a33e3905e28c9f0dddf355c84eb504e3224b"),
        (4, 2, 4096, "3839881147ab5c7b40370dac08433f90c2fc1ea99770b729a1511dbca442bf4e"),
        (6, 4, 128, "67f69071cc8f5c190f1e1b7c42cc5ade41378b692953acb85ed440a8d041c8c3"),
        (10, 4, 257, "bfeef581247166e1ba6241817d8fa3ebdbbb0c4c799d5198decf95c336cea664"),
        (16, 16, 33, "914e04ce0e9840c0630c71cb014afcd2b1b9557268f4fac1af2c76b027d9d3f5"),
        (32, 8, 100, "0ee20109b910b1138da96227435ec884cbac3208dc126e7b9858a740e9310e48"),
        (100, 3, 17, "c34d84c611b83320f6092f2ec7408fb914d715051d6a1c3dc0ac6a2305bbb455"),
    ];
    fn pinned_rows(k: usize, m: usize, symbols: usize) -> Vec<Vec<u16>> {
        (0..k)
            .map(|row| {
                let seed = 0xC0DE ^ ((k * 10_000 + m * 100 + row) as u64) ^ (symbols as u64) << 32;
                reference::bytes(seed, 2 * symbols)
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect()
            })
            .collect()
    }
    /// The owned-row parity API matches the independent reference on every backend,
    /// including stripes wider than one kernel group.
    #[test]
    fn owned_row_parity_matches_reference_and_pinned_digests() {
        for &(k, m, symbols, expected) in PINNED_PARITY {
            let data = pinned_rows(k, m, symbols);
            let reference = reference::encode_parity(&data, m);
            let bytes = reference
                .iter()
                .flatten()
                .flat_map(|symbol| symbol.to_le_bytes())
                .collect::<Vec<_>>();
            assert_eq!(
                reference::digest(&bytes),
                expected,
                "reference {k}+{m} symbols {symbols}"
            );
            assert_eq!(encode_parity(&data, m).unwrap(), reference);
            for backend in host_backends() {
                assert_eq!(
                    encode_parity_with_backend(&data, m, backend).unwrap(),
                    reference,
                    "{backend:?} {k}+{m} symbols {symbols}"
                );
            }
        }
    }
    #[test]
    fn owned_row_parity_rejects_ragged_rows_and_unrepresentable_stripes() {
        assert_eq!(encode_parity(&[], 3).unwrap(), Vec::<Vec<u16>>::new());
        assert_eq!(
            encode_parity(&[vec![1, 2]], 0).unwrap(),
            Vec::<Vec<u16>>::new()
        );
        assert!(encode_parity(&[vec![1, 2], vec![3]], 1).is_err());
        assert!(encode_parity(&[vec![1]], ORDER_MINUS_ONE).is_err());
        assert!(encode_parity(&[Vec::new()], ORDER_MINUS_ONE).is_err());
        assert_eq!(
            encode_parity(&[Vec::new(), Vec::new()], 2).unwrap(),
            vec![Vec::<u16>::new(); 2]
        );
        assert_eq!(
            encode_parity(&[vec![0x1234, 0]], 2).unwrap(),
            vec![vec![0x1234, 0], vec![0x1234, 0]]
        );
    }
    #[test]
    fn symbols_from_chunk_packs_pairs() {
        assert_eq!(
            symbols_from_chunk(2, &[0x01, 0x02, 0x03]),
            vec![0x0201, 0x0003]
        );
        assert_eq!(symbols_from_chunk(3, &[0x01, 0x02]), vec![0x0201, 0, 0]);
        assert_eq!(
            symbols_from_chunk(1, &[0x01, 0x02, 0x03, 0x04]),
            vec![0x0201]
        );
        assert_eq!(symbols_from_chunk(2, &[]), vec![0, 0]);
        assert_eq!(symbols_from_chunk(0, &[0x01]), Vec::<u16>::new());
    }
    #[test]
    fn parity_coefficients_reject_invalid_field_geometry_before_allocation() {
        assert!(parity_coefficients(0, 1).is_err());
        assert!(parity_coefficients(1, 0).is_err());
        assert!(parity_coefficients(ORDER_MINUS_ONE, 1).is_err());
        assert!(parity_coefficients(usize::MAX, 1).is_err());
    }
    #[test]
    fn parity_offset_matches_expected() {
        let offset = parity_offset(100, 2, 1, 3, 16).expect("offset");
        assert_eq!(offset, 100 + (2 * 3 + 1) as u64 * 16);
    }
}
