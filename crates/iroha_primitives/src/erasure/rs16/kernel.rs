//! GF(2^16) row kernels: `destination = sum(coefficient * source)` over little-endian symbols.
//!
//! Multiplication by a constant is linear over GF(2), so `c * s` is the XOR of `c * (n << 4i)`
//! for the four nibbles `n` of `s`. Every kernel call tabulates each coefficient's products
//! once, outside its symbol loops: four 16-entry tables per result byte drive NEON `TBL` and
//! AVX2 `VPSHUFB` lookups, and two 256-entry tables drive the scalar fallback. All backends
//! therefore compute the same exact field products, independent of the host's hardware.
//! Rows are read and written directly as little-endian byte pairs; nothing is staged.
use super::Backend;

/// Sources one pass accumulates in registers before writing its destination once.
/// Every protocol stripe (at most 16 data rows) needs a single pass per output row.
pub(super) const GROUP: usize = 16;

/// Multiply by `x` modulo x^16 + x^12 + x^3 + x + 1.
const fn xtime(value: u16) -> u16 {
    (value << 1) ^ if value & 0x8000 != 0 { 0x100B } else { 0 }
}

/// `coefficient * x^bit` for every bit position of a symbol.
fn basis(coefficient: u16) -> [u16; 16] {
    let mut basis = [0; 16];
    let mut value = coefficient;
    for slot in &mut basis {
        *slot = value;
        value = xtime(value);
    }
    basis
}

/// Products of the `log2(N)` basis entries from `offset` with every value below `N`, built
/// by linearity: each value adds its lowest set bit's basis product to an earlier entry.
fn products<const N: usize>(basis: &[u16; 16], offset: usize) -> [u16; N] {
    let mut products = [0u16; N];
    for value in 1..N {
        products[value] =
            products[value & (value - 1)] ^ basis[offset + value.trailing_zeros() as usize];
    }
    products
}

/// One coefficient's products with each nibble value at each nibble position of a symbol.
/// Entries `0..4` hold the result low bytes for nibble positions 0..4, entries `4..8` the
/// result high bytes.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub(super) struct NibbleTables([[u8; 16]; 8]);

impl NibbleTables {
    const ZERO: Self = Self([[0; 16]; 8]);

    pub(super) fn new(coefficient: u16) -> Self {
        let basis = basis(coefficient);
        let mut tables = Self::ZERO;
        for position in 0..4 {
            let products = products::<16>(&basis, 4 * position);
            for (value, product) in products.iter().enumerate() {
                let [low, high] = product.to_le_bytes();
                tables.0[position][value] = low;
                tables.0[4 + position][value] = high;
            }
        }
        tables
    }

    /// Exact product with one symbol; SIMD row tails use the same tables as the vectors.
    pub(super) fn mul(&self, symbol: u16) -> u16 {
        let [low, high] = symbol.to_le_bytes();
        let nibbles = [low & 0x0F, low >> 4, high & 0x0F, high >> 4].map(usize::from);
        let table = &self.0;
        u16::from_le_bytes([
            table[0][nibbles[0]]
                ^ table[1][nibbles[1]]
                ^ table[2][nibbles[2]]
                ^ table[3][nibbles[3]],
            table[4][nibbles[0]]
                ^ table[5][nibbles[1]]
                ^ table[6][nibbles[2]]
                ^ table[7][nibbles[3]],
        ])
    }
}

/// One coefficient's products with every low byte and every high byte of a symbol.
pub(super) struct ByteTables {
    low: [u16; 256],
    high: [u16; 256],
}

impl ByteTables {
    pub(super) fn new(coefficient: u16) -> Self {
        let basis = basis(coefficient);
        Self {
            low: products::<256>(&basis, 0),
            high: products::<256>(&basis, 8),
        }
    }

    /// Exact product with one symbol from two table lookups.
    pub(super) fn mul(&self, symbol: u16) -> u16 {
        let [low, high] = symbol.to_le_bytes();
        self.low[usize::from(low)] ^ self.high[usize::from(high)]
    }
}

/// Write `sum(coefficient * source)` over little-endian GF(2^16) symbols into `destination`,
/// or XOR it into the existing contents when `accumulate` is set.
///
/// Zero coefficients are skipped; an empty overwrite zeroes the destination. Terms are
/// accumulated [`GROUP`] at a time, so the destination is written once per group.
///
/// # Panics
/// If the destination length is odd or any nonzero term's source length differs from it.
// Argument-position `impl Trait` cannot elide the source lifetime on stable Rust.
#[allow(single_use_lifetimes)]
pub(super) fn combine<'a>(
    terms: impl IntoIterator<Item = (u16, &'a [u8])>,
    destination: &mut [u8],
    mut accumulate: bool,
    backend: Backend,
) {
    assert!(
        destination.len().is_multiple_of(2),
        "RS16 rows hold whole symbols"
    );
    let mut coefficients = [0u16; GROUP];
    let mut sources: [&[u8]; GROUP] = [&[]; GROUP];
    let mut pending = 0;
    for (coefficient, source) in terms {
        if coefficient == 0 {
            continue;
        }
        assert_eq!(source.len(), destination.len(), "RS16 rows share one width");
        coefficients[pending] = coefficient;
        sources[pending] = source;
        pending += 1;
        if pending == GROUP {
            apply(backend, &coefficients, &sources, destination, accumulate);
            pending = 0;
            accumulate = true;
        }
    }
    if pending != 0 {
        apply(
            backend,
            &coefficients[..pending],
            &sources[..pending],
            destination,
            accumulate,
        );
    } else if !accumulate {
        destination.fill(0);
    }
}

/// Run one group of at most [`GROUP`] terms whose sources all have the destination's length.
#[allow(unsafe_code)]
fn apply(
    backend: Backend,
    coefficients: &[u16],
    sources: &[&[u8]],
    destination: &mut [u8],
    accumulate: bool,
) {
    assert!(coefficients.len() == sources.len() && coefficients.len() <= GROUP);
    assert!(
        destination.len().is_multiple_of(2)
            && sources
                .iter()
                .all(|source| source.len() == destination.len())
    );
    match backend {
        Backend::Scalar => scalar(coefficients, sources, destination, accumulate),
        #[cfg(all(
            feature = "simd-accel",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        // SAFETY: Backend::Avx2 is only selected when AVX2 is detected; the group size and
        // every source length were checked above.
        Backend::Avx2 => unsafe { avx2::apply(coefficients, sources, destination, accumulate) },
        #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
        // SAFETY: Backend::Neon is only selected when NEON is detected; the group size and
        // every source length were checked above.
        Backend::Neon => unsafe { neon::apply(coefficients, sources, destination, accumulate) },
    }
}

/// Rows shorter than this many bytes use the cheaper-to-build nibble tables in scalar code.
const SMALL_ROW_BYTES: usize = 512;

/// Portable kernel. Long rows use one 256-entry table pair per term and one pass per source
/// row; short rows amortize tables poorly and use the nibble tables in one pass instead.
fn scalar(coefficients: &[u16], sources: &[&[u8]], destination: &mut [u8], accumulate: bool) {
    if destination.len() < SMALL_ROW_BYTES {
        let mut tables = [NibbleTables::ZERO; GROUP];
        for (table, coefficient) in tables.iter_mut().zip(coefficients) {
            *table = NibbleTables::new(*coefficient);
        }
        tail(
            &tables[..coefficients.len()],
            sources,
            destination,
            0,
            accumulate,
        );
        return;
    }
    for (index, (coefficient, source)) in coefficients.iter().zip(sources).enumerate() {
        let tables = ByteTables::new(*coefficient);
        let pairs = destination.chunks_exact_mut(2).zip(source.chunks_exact(2));
        if index == 0 && !accumulate {
            for (output, input) in pairs {
                let product = tables.mul(u16::from_le_bytes([input[0], input[1]]));
                output.copy_from_slice(&product.to_le_bytes());
            }
        } else {
            for (output, input) in pairs {
                let product = tables.mul(u16::from_le_bytes([input[0], input[1]]))
                    ^ u16::from_le_bytes([output[0], output[1]]);
                output.copy_from_slice(&product.to_le_bytes());
            }
        }
    }
}

/// Scalar pass from byte `offset` with nibble tables: SIMD row tails and short scalar rows.
fn tail(
    tables: &[NibbleTables],
    sources: &[&[u8]],
    destination: &mut [u8],
    offset: usize,
    accumulate: bool,
) {
    for position in (offset..destination.len()).step_by(2) {
        let mut value = if accumulate {
            u16::from_le_bytes([destination[position], destination[position + 1]])
        } else {
            0
        };
        for (table, source) in tables.iter().zip(sources) {
            value ^= table.mul(u16::from_le_bytes([source[position], source[position + 1]]));
        }
        destination[position..position + 2].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
#[allow(unsafe_code)]
mod neon {
    use super::{GROUP, NibbleTables, tail};
    use std::arch::aarch64::{
        uint8x16_t, uint8x16x2_t, uint8x16x4_t, vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8_x4,
        vld2q_u8, vqtbl1q_u8, vshrq_n_u8, vst2q_u8,
    };

    /// NEON pass: `LD2` splits 16 symbols into low and high bytes, eight `TBL` lookups form
    /// each product, and `ST2` re-interleaves the accumulated little-endian symbols.
    ///
    /// # Safety
    /// NEON must be available, at most [`GROUP`] terms may be given, and every source must
    /// hold exactly `destination.len()` bytes.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn apply(
        coefficients: &[u16],
        sources: &[&[u8]],
        destination: &mut [u8],
        accumulate: bool,
    ) {
        let mut tables = [NibbleTables::ZERO; GROUP];
        for (table, coefficient) in tables.iter_mut().zip(coefficients) {
            *table = NibbleTables::new(*coefficient);
        }
        let tables = &tables[..coefficients.len()];
        let len = destination.len();
        let output = destination.as_mut_ptr();
        let mut offset = 0;
        // SAFETY: NEON is available. Each block reads and writes `offset..offset + 64` (or 32)
        // bytes only after checking that range against `len`, and every source has `len` bytes.
        unsafe {
            let mask = vdupq_n_u8(0x0F);
            let zero = uint8x16x2_t(vdupq_n_u8(0), vdupq_n_u8(0));
            while offset + 64 <= len {
                let (mut first, mut second) = if accumulate {
                    (
                        vld2q_u8(output.add(offset)),
                        vld2q_u8(output.add(offset + 32)),
                    )
                } else {
                    (zero, zero)
                };
                for (table, source) in tables.iter().zip(sources) {
                    let (low, high) = load(table);
                    let input = source.as_ptr().add(offset);
                    first = multiply_add(first, vld2q_u8(input), low, high, mask);
                    second = multiply_add(second, vld2q_u8(input.add(32)), low, high, mask);
                }
                vst2q_u8(output.add(offset), first);
                vst2q_u8(output.add(offset + 32), second);
                offset += 64;
            }
            if offset + 32 <= len {
                let mut block = if accumulate {
                    vld2q_u8(output.add(offset))
                } else {
                    zero
                };
                for (table, source) in tables.iter().zip(sources) {
                    let (low, high) = load(table);
                    block = multiply_add(
                        block,
                        vld2q_u8(source.as_ptr().add(offset)),
                        low,
                        high,
                        mask,
                    );
                }
                vst2q_u8(output.add(offset), block);
                offset += 32;
            }
        }
        tail(tables, sources, destination, offset, accumulate);
    }

    /// Load the low-byte and high-byte table quadruples of one coefficient.
    #[inline]
    unsafe fn load(tables: &NibbleTables) -> (uint8x16x4_t, uint8x16x4_t) {
        let base = tables.0.as_ptr().cast::<u8>();
        // SAFETY: `base` spans all 128 table bytes; each half is four contiguous vectors.
        unsafe { (vld1q_u8_x4(base), vld1q_u8_x4(base.add(64))) }
    }

    /// `accumulator ^ coefficient * symbols` for 16 symbols split into low and high bytes.
    #[inline]
    unsafe fn multiply_add(
        accumulator: uint8x16x2_t,
        symbols: uint8x16x2_t,
        low: uint8x16x4_t,
        high: uint8x16x4_t,
        mask: uint8x16_t,
    ) -> uint8x16x2_t {
        // SAFETY: the caller guarantees NEON; these intrinsics only touch registers.
        unsafe {
            let n0 = vandq_u8(symbols.0, mask);
            let n1 = vshrq_n_u8::<4>(symbols.0);
            let n2 = vandq_u8(symbols.1, mask);
            let n3 = vshrq_n_u8::<4>(symbols.1);
            let product_low = veorq_u8(
                veorq_u8(vqtbl1q_u8(low.0, n0), vqtbl1q_u8(low.1, n1)),
                veorq_u8(vqtbl1q_u8(low.2, n2), vqtbl1q_u8(low.3, n3)),
            );
            let product_high = veorq_u8(
                veorq_u8(vqtbl1q_u8(high.0, n0), vqtbl1q_u8(high.1, n1)),
                veorq_u8(vqtbl1q_u8(high.2, n2), vqtbl1q_u8(high.3, n3)),
            );
            uint8x16x2_t(
                veorq_u8(accumulator.0, product_low),
                veorq_u8(accumulator.1, product_high),
            )
        }
    }
}

#[cfg(all(
    feature = "simd-accel",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[allow(unsafe_code)]
mod avx2 {
    use super::{GROUP, NibbleTables, tail};
    use arch::{
        __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_broadcastsi128_si256,
        _mm256_loadu_si256, _mm256_packus_epi16, _mm256_set1_epi8, _mm256_set1_epi16,
        _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_srli_epi16, _mm256_storeu_si256,
        _mm256_unpackhi_epi8, _mm256_unpacklo_epi8, _mm256_xor_si256,
    };
    #[cfg(target_arch = "x86")]
    use std::arch::x86 as arch;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64 as arch;

    /// AVX2 pass over 32 symbols per block. `VPACKUSWB` gathers the low and the high bytes of
    /// two vectors (lane-wise, so symbols 0-7, 16-23 | 8-15, 24-31), eight `VPSHUFB` lookups
    /// form each product byte vector, and `VPUNPCKLBW`/`VPUNPCKHBW` invert exactly that
    /// lane-wise packing back into the first and second vector's little-endian symbols.
    ///
    /// # Safety
    /// AVX2 must be available, at most [`GROUP`] terms may be given, and every source must
    /// hold exactly `destination.len()` bytes.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn apply(
        coefficients: &[u16],
        sources: &[&[u8]],
        destination: &mut [u8],
        accumulate: bool,
    ) {
        let mut tables = [NibbleTables::ZERO; GROUP];
        for (table, coefficient) in tables.iter_mut().zip(coefficients) {
            *table = NibbleTables::new(*coefficient);
        }
        let tables = &tables[..coefficients.len()];
        let len = destination.len();
        let output = destination.as_mut_ptr();
        let mut offset = 0;
        // SAFETY: AVX2 is available. Each block reads and writes `offset..offset + 64` (or
        // 32) bytes only after checking that range against `len`, and every source has `len`
        // bytes. All loads and stores are unaligned.
        unsafe {
            let low_bytes = _mm256_set1_epi16(0x00FF);
            let nibble = _mm256_set1_epi8(0x0F);
            while offset + 64 <= len {
                let mut product_low = _mm256_setzero_si256();
                let mut product_high = _mm256_setzero_si256();
                for (table, source) in tables.iter().zip(sources) {
                    let input = source.as_ptr().add(offset);
                    let first = _mm256_loadu_si256(input.cast());
                    let second = _mm256_loadu_si256(input.add(32).cast());
                    let (low, high) = split(first, second, low_bytes);
                    let (term_low, term_high) = multiply(table, low, high, nibble);
                    product_low = _mm256_xor_si256(product_low, term_low);
                    product_high = _mm256_xor_si256(product_high, term_high);
                }
                let mut first = _mm256_unpacklo_epi8(product_low, product_high);
                let mut second = _mm256_unpackhi_epi8(product_low, product_high);
                if accumulate {
                    first = _mm256_xor_si256(first, _mm256_loadu_si256(output.add(offset).cast()));
                    second = _mm256_xor_si256(
                        second,
                        _mm256_loadu_si256(output.add(offset + 32).cast()),
                    );
                }
                _mm256_storeu_si256(output.add(offset).cast(), first);
                _mm256_storeu_si256(output.add(offset + 32).cast(), second);
                offset += 64;
            }
            if offset + 32 <= len {
                let mut product_low = _mm256_setzero_si256();
                let mut product_high = _mm256_setzero_si256();
                for (table, source) in tables.iter().zip(sources) {
                    let first = _mm256_loadu_si256(source.as_ptr().add(offset).cast());
                    let (low, high) = split(first, _mm256_setzero_si256(), low_bytes);
                    let (term_low, term_high) = multiply(table, low, high, nibble);
                    product_low = _mm256_xor_si256(product_low, term_low);
                    product_high = _mm256_xor_si256(product_high, term_high);
                }
                let mut first = _mm256_unpacklo_epi8(product_low, product_high);
                if accumulate {
                    first = _mm256_xor_si256(first, _mm256_loadu_si256(output.add(offset).cast()));
                }
                _mm256_storeu_si256(output.add(offset).cast(), first);
                offset += 32;
            }
        }
        tail(tables, sources, destination, offset, accumulate);
    }

    /// Gather the low bytes and the high bytes of 32 little-endian symbols, lane-wise.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn split(first: __m256i, second: __m256i, low_bytes: __m256i) -> (__m256i, __m256i) {
        (
            _mm256_packus_epi16(
                _mm256_and_si256(first, low_bytes),
                _mm256_and_si256(second, low_bytes),
            ),
            _mm256_packus_epi16(
                _mm256_srli_epi16::<8>(first),
                _mm256_srli_epi16::<8>(second),
            ),
        )
    }

    /// Broadcast one 16-byte table to both 128-bit lanes.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn broadcast(row: &[u8; 16]) -> __m256i {
        // SAFETY: `row` is 16 readable bytes and AVX2 is enabled for this function.
        unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(row.as_ptr().cast())) }
    }

    /// Product low and high bytes of one coefficient with lane-wise split symbol bytes.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn multiply(
        tables: &NibbleTables,
        low: __m256i,
        high: __m256i,
        nibble: __m256i,
    ) -> (__m256i, __m256i) {
        // SAFETY: AVX2 is enabled for this function and every table row is 16 bytes.
        unsafe {
            let nibbles = [
                _mm256_and_si256(low, nibble),
                _mm256_and_si256(_mm256_srli_epi16::<4>(low), nibble),
                _mm256_and_si256(high, nibble),
                _mm256_and_si256(_mm256_srli_epi16::<4>(high), nibble),
            ];
            let mut product_low = _mm256_setzero_si256();
            let mut product_high = _mm256_setzero_si256();
            for (position, nibbles) in nibbles.into_iter().enumerate() {
                product_low = _mm256_xor_si256(
                    product_low,
                    _mm256_shuffle_epi8(broadcast(&tables.0[position]), nibbles),
                );
                product_high = _mm256_xor_si256(
                    product_high,
                    _mm256_shuffle_epi8(broadcast(&tables.0[4 + position]), nibbles),
                );
            }
            (product_low, product_high)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{host_backends, reference};
    use super::*;

    /// Coefficients at the special values, reduction boundaries and arbitrary points.
    const COEFFICIENTS: [u16; 12] = [
        1, 2, 3, 0x00FF, 0x0100, 0x8000, 0x100B, 0x1234, 0x8001, 0xBEEF, 0xFFFE, 0xFFFF,
    ];

    #[test]
    fn product_tables_match_bit_serial_multiply_for_every_symbol() {
        let mut state = 0x2545_F491_u32;
        let random = std::iter::from_fn(|| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            Some(u16::try_from(state >> 16).expect("shifted"))
        });
        for coefficient in COEFFICIENTS.into_iter().chain(random.take(20)) {
            let nibbles = NibbleTables::new(coefficient);
            let bytes = ByteTables::new(coefficient);
            for symbol in 0..=u16::MAX {
                let expected = reference::mul(coefficient, symbol);
                assert_eq!(
                    nibbles.mul(symbol),
                    expected,
                    "{coefficient:#x}*{symbol:#x}"
                );
                assert_eq!(bytes.mul(symbol), expected, "{coefficient:#x}*{symbol:#x}");
            }
        }
        let (zero_nibbles, zero_bytes) = (NibbleTables::new(0), ByteTables::new(0));
        assert!((0..=u16::MAX).all(|symbol| zero_nibbles.mul(symbol) == 0));
        assert!((0..=u16::MAX).all(|symbol| zero_bytes.mul(symbol) == 0));
        assert_eq!(xtime(0x8000), 0x100B);
        assert_eq!(basis(1)[15], 0x8000);
    }

    fn row(seed: u64, symbols: usize) -> Vec<u8> {
        let mut bytes = reference::bytes(seed, 2 * symbols);
        // Every fifth symbol is zero and every seventh all-ones: table and lane edge cases.
        for (index, pair) in bytes.chunks_exact_mut(2).enumerate() {
            if index % 5 == 0 {
                pair.fill(0);
            } else if index % 7 == 0 {
                pair.fill(0xFF);
            }
        }
        bytes
    }

    fn expected(terms: &[(u16, Vec<u8>)], start: Option<&[u8]>, symbols: usize) -> Vec<u8> {
        (0..symbols)
            .flat_map(|position| {
                let read = |bytes: &[u8]| {
                    u16::from_le_bytes([bytes[2 * position], bytes[2 * position + 1]])
                };
                terms
                    .iter()
                    .fold(start.map_or(0, read), |acc, (coefficient, source)| {
                        acc ^ reference::mul(*coefficient, read(source))
                    })
                    .to_le_bytes()
            })
            .collect()
    }

    /// Every backend overwrites with exactly the reference combination for every SIMD block
    /// and tail length, every coefficient class, zero coefficients and more terms than one
    /// group, regardless of the destination's previous contents.
    #[test]
    fn combine_matches_reference_on_every_backend_length_and_group_size() {
        let lengths = (0..=70).chain([95, 96, 97, 128, 129, 255, 256, 257, 1000]);
        for symbols in lengths {
            for count in [0usize, 1, 2, 4, 15, 16, 17, 21, 33] {
                let terms = (0..count)
                    .map(|index| {
                        let coefficient = match index % 4 {
                            0 => COEFFICIENTS[(index + symbols) % COEFFICIENTS.len()],
                            1 => 0,
                            _ => u16::try_from((index * 7919 + symbols * 104_729) % 65_536)
                                .expect("masked"),
                        };
                        (coefficient, row((index * 1000 + symbols) as u64, symbols))
                    })
                    .collect::<Vec<_>>();
                let want = expected(&terms, None, symbols);
                for backend in host_backends() {
                    let mut destination = row(0xD1E7, symbols);
                    combine(
                        terms.iter().map(|(c, source)| (*c, source.as_slice())),
                        &mut destination,
                        false,
                        backend,
                    );
                    assert!(
                        destination == want,
                        "{backend:?} symbols {symbols} terms {count}"
                    );
                }
            }
        }
    }

    /// Accumulating combinations (owned-row groups after the first) XOR exactly the reference
    /// sum into the destination, across group boundaries and with zero coefficients; a group
    /// and the shared nibble tail agree with it directly.
    #[test]
    fn accumulating_combinations_match_reference_on_every_backend() {
        for symbols in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 300] {
            let start = row(77, symbols);
            let terms = COEFFICIENTS
                .iter()
                .copied()
                .chain([0, 0x4321, 0, 7, 0x9000, 1, 0xFFFF, 0x0F0F, 2])
                .enumerate()
                .map(|(index, coefficient)| (coefficient, row(index as u64 + 5, symbols)))
                .collect::<Vec<_>>();
            let want = expected(&terms, Some(&start), symbols);
            let group = &terms[..GROUP.min(COEFFICIENTS.len())];
            let group_want = expected(group, Some(&start), symbols);
            let coefficients = group.iter().map(|(c, _)| *c).collect::<Vec<_>>();
            let sources = group.iter().map(|(_, s)| s.as_slice()).collect::<Vec<_>>();
            for backend in host_backends() {
                let mut destination = start.clone();
                combine(
                    terms.iter().map(|(c, source)| (*c, source.as_slice())),
                    &mut destination,
                    true,
                    backend,
                );
                assert!(destination == want, "{backend:?} symbols {symbols}");
                let mut destination = start.clone();
                apply(backend, &coefficients, &sources, &mut destination, true);
                assert!(
                    destination == group_want,
                    "{backend:?} group symbols {symbols}"
                );
                let mut destination = start.clone();
                let zeros = terms.iter().map(|(_, source)| (0, source.as_slice()));
                combine(zeros.clone(), &mut destination, true, backend);
                assert!(destination == start, "{backend:?} empty accumulate");
                combine(zeros, &mut destination, false, backend);
                assert!(
                    destination.iter().all(|byte| *byte == 0),
                    "{backend:?} empty"
                );
            }
            let mut destination = start.clone();
            let tables = coefficients
                .iter()
                .map(|c| NibbleTables::new(*c))
                .collect::<Vec<_>>();
            tail(&tables, &sources, &mut destination, 0, true);
            assert!(destination == group_want, "tail symbols {symbols}");
        }
    }

    #[test]
    #[should_panic(expected = "RS16 rows share one width")]
    fn combine_rejects_mismatched_row_widths() {
        let mut destination = vec![0; 4];
        combine(
            [(1, &[0u8; 2][..])],
            &mut destination,
            false,
            Backend::Scalar,
        );
    }

    #[test]
    #[should_panic(expected = "RS16 rows hold whole symbols")]
    fn combine_rejects_partial_symbols() {
        let mut destination = vec![0; 3];
        combine(
            [(1, &[0u8; 3][..])],
            &mut destination,
            false,
            Backend::Scalar,
        );
    }
}
