//! Compact terminal stripes over the shared RS16 field and row kernels.
//! No signed context, consensus resource cap, custody decision or protocol signature lives here.
//! The caller owns every job buffer. Existing process-wide field tables remain separate.
//! Rows are encoded and decoded in place as little-endian byte rows of the caller's buffers.
#[path = "compact/funded.rs"]
mod funded;
pub use funded::{
    CodecAllocationError, Encoded, Reconstructed, encode_funded, reconstruct_funded,
    required_backing_bytes,
};

use super::{Backend, Rs16Error, choose_backend, invert, kernel, prepare};
use std::ops::Range;

/// Checked byte geometry; one stripe has k data rows followed by m parity rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactShape {
    payload: usize,
    k: usize,
    m: usize,
    maximum_row: usize,
    stripes: usize,
    terminal_row: usize,
    chunks: usize,
    encoded: usize,
    workspace: usize,
}
impl CompactShape {
    /// Calculate exact geometry and caller-owned scratch without allocating.
    /// All final data padding is zero; the terminal row is 2*ceil(remaining/(2*k)).
    ///
    /// # Errors
    /// Returns [`Rs16Error`] for an empty payload, invalid row or shard counts,
    /// or geometry whose backing sizes overflow the host's address space.
    pub fn new(payload: usize, k: usize, m: usize, maximum_row: usize) -> Result<Self, Rs16Error> {
        let n = k.checked_add(m).ok_or(Rs16Error)?;
        if payload == 0
            || k == 0
            || m == 0
            || n > u16::MAX as usize
            || maximum_row < 2
            || !maximum_row.is_multiple_of(2)
        {
            return Err(Rs16Error);
        }
        let capacity = k.checked_mul(maximum_row).ok_or(Rs16Error)?;
        let stripes = payload.div_ceil(capacity);
        let remaining = payload - (stripes - 1) * capacity;
        let terminal_row = remaining.div_ceil(2 * k).checked_mul(2).ok_or(Rs16Error)?;
        let chunks = stripes.checked_mul(n).ok_or(Rs16Error)?;
        let encoded = (stripes - 1)
            .checked_mul(maximum_row)
            .and_then(|v| v.checked_add(terminal_row))
            .and_then(|v| v.checked_mul(n))
            .ok_or(Rs16Error)?;
        let active_row = if stripes == 1 {
            terminal_row
        } else {
            maximum_row
        };
        // TODO: the `(n + k) * active_row / 2` row-staging term no longer backs codec work
        // (rows are coded in place); drop it together with the consensus admission budgets
        // derived from `workspace_words` and `required_backing_bytes`.
        let workspace = k
            .checked_mul(k)
            .and_then(|v| v.checked_mul(2))
            .and_then(|v| v.checked_add(k.checked_mul(m)?))
            .and_then(|v| v.checked_add(k))
            .and_then(|v| v.checked_add(n.checked_add(k)?.checked_mul(active_row / 2)?))
            .ok_or(Rs16Error)?;
        Ok(Self {
            payload,
            k,
            m,
            maximum_row,
            stripes,
            terminal_row,
            chunks,
            encoded,
            workspace,
        })
    }
    /// Number of stripes in this exact compact codeword.
    pub fn stripe_count(self) -> usize {
        self.stripes
    }
    /// Exact row length of the terminal stripe.
    pub fn terminal_row_bytes(self) -> usize {
        self.terminal_row
    }
    /// Canonical original payload length.
    pub fn payload_bytes(self) -> usize {
        self.payload
    }
    /// Exact complete codeword bytes, excluding any wire/authentication metadata.
    pub fn encoded_bytes(self) -> usize {
        self.encoded
    }
    /// Number of ordered chunks.
    pub fn chunk_count(self) -> usize {
        self.chunks
    }
    /// Required caller-owned u16 workspace elements.
    pub fn workspace_words(self) -> usize {
        self.workspace
    }
    /// Exact byte range of one row in the complete ordered codeword.
    pub fn chunk_range(self, index: usize) -> Option<Range<usize>> {
        if index >= self.chunks {
            return None;
        }
        let n = self.k + self.m;
        let stripe = index / n;
        let row_bytes = self.row_bytes(stripe);
        let start = stripe * n * self.maximum_row + (index % n) * row_bytes;
        Some(start..start + row_bytes)
    }
    fn row_bytes(self, stripe: usize) -> usize {
        if stripe + 1 == self.stripes {
            self.terminal_row
        } else {
            self.maximum_row
        }
    }
    /// Contiguous codeword bytes of one stripe: its k data rows, then its m parity rows.
    fn stripe_range(self, stripe: usize) -> Range<usize> {
        let n = self.k + self.m;
        let start = stripe * n * self.maximum_row;
        start..start + n * self.row_bytes(stripe)
    }
    /// Encode exact canonical bytes without allocating any per-job backing.
    ///
    /// # Errors
    /// Returns [`Rs16Error`] when input or output lengths differ from this shape,
    /// workspace is too short, or the encoding matrix cannot be inverted.
    pub fn encode_into(
        self,
        payload: &[u8],
        codeword: &mut [u8],
        workspace: &mut [u16],
    ) -> Result<(), Rs16Error> {
        self.encode_with_backend(payload, codeword, workspace, choose_backend())
    }
    fn encode_with_backend(
        self,
        payload: &[u8],
        codeword: &mut [u8],
        workspace: &mut [u16],
        backend: Backend,
    ) -> Result<(), Rs16Error> {
        if payload.len() != self.payload
            || codeword.len() != self.encoded
            || workspace.len() < self.workspace
        {
            return Err(Rs16Error);
        }
        let work = Work::new(self, workspace);
        prepare(self.k, self.m, work.matrix, work.inverse, work.parity)?;
        for stripe in 0..self.stripes {
            let row_bytes = self.row_bytes(stripe);
            let (data, parity) =
                codeword[self.stripe_range(stripe)].split_at_mut(self.k * row_bytes);
            let offset = stripe * self.k * self.maximum_row;
            let remaining = (self.payload - offset).min(self.k * row_bytes);
            data[..remaining].copy_from_slice(&payload[offset..offset + remaining]);
            data[remaining..].fill(0);
            encode_parity_rows(self.k, row_bytes, work.parity, data, parity, backend);
        }
        Ok(())
    }
    /// Recover from any k received rows per stripe and check every provided row,
    /// canonical zero padding, and every regenerated row through the caller's
    /// commitment predicate. This predicate must bind the original manifest;
    /// this codec does not authenticate a manifest or choose an authority.
    /// On error, destinations may be partly written and must not be treated as output.
    ///
    /// # Errors
    /// Returns [`Rs16Error`] for incorrect buffer or row lengths, insufficient or
    /// inconsistent received rows, a singular decoding matrix, nonzero padding,
    /// or a regenerated row rejected by `verify_original_row`.
    pub fn reconstruct_into(
        self,
        received: &[Option<&[u8]>],
        payload: &mut [u8],
        codeword: &mut [u8],
        workspace: &mut [u16],
        verify_original_row: impl FnMut(usize, &[u8]) -> bool,
    ) -> Result<(), Rs16Error> {
        self.reconstruct_with_backend(
            received,
            payload,
            codeword,
            workspace,
            verify_original_row,
            choose_backend(),
        )
    }
    fn reconstruct_with_backend(
        self,
        received: &[Option<&[u8]>],
        payload: &mut [u8],
        codeword: &mut [u8],
        workspace: &mut [u16],
        mut verify_original_row: impl FnMut(usize, &[u8]) -> bool,
        backend: Backend,
    ) -> Result<(), Rs16Error> {
        if received.len() != self.chunks
            || payload.len() != self.payload
            || codeword.len() != self.encoded
            || workspace.len() < self.workspace
        {
            return Err(Rs16Error);
        }
        let work = Work::new(self, workspace);
        prepare(self.k, self.m, work.matrix, work.inverse, work.parity)?;
        let n = self.k + self.m;
        for stripe in 0..self.stripes {
            let row_bytes = self.row_bytes(stripe);
            let rows = &received[stripe * n..(stripe + 1) * n];
            let mut selected = 0;
            for (index, row) in rows.iter().enumerate() {
                let Some(row) = row else {
                    continue;
                };
                if row.len() != row_bytes {
                    return Err(Rs16Error);
                }
                if selected < self.k {
                    work.indices[selected] = u16::try_from(index).map_err(|_| Rs16Error)?;
                    selected += 1;
                }
            }
            if selected != self.k {
                return Err(Rs16Error);
            }
            // The selection is every present data row, then the first `k - present_data`
            // present parity rows. Regenerating a selected row reproduces it exactly
            // (`G_S * G_S^-1 = I`), so selected rows are copied; every other row is decoded
            // or re-encoded and then checked against any received copy below. Only missing
            // data rows need the decoding matrix.
            let present_data = rows[..self.k].iter().filter(|row| row.is_some()).count();
            if present_data < self.k {
                work.matrix.fill(0);
                for (row, index) in work.indices.iter().map(|v| usize::from(*v)).enumerate() {
                    if index < self.k {
                        work.matrix[row * self.k + index] = 1;
                    } else {
                        work.matrix[row * self.k..(row + 1) * self.k].copy_from_slice(
                            &work.parity[(index - self.k) * self.k..(index - self.k + 1) * self.k],
                        );
                    }
                }
                invert(self.k, work.matrix, work.inverse)?;
            }
            let stripe_range = self.stripe_range(stripe);
            let (data, parity) = codeword[stripe_range.clone()].split_at_mut(self.k * row_bytes);
            for (row, (output, coefficients)) in data
                .chunks_exact_mut(row_bytes)
                .zip(work.inverse.chunks_exact(self.k))
                .enumerate()
            {
                if let Some(present) = rows[row] {
                    output.copy_from_slice(present);
                } else {
                    kernel::combine(
                        coefficients
                            .iter()
                            .copied()
                            .zip(rows.iter().flatten().copied()),
                        output,
                        backend,
                    );
                }
            }
            let mut selected_parity = self.k - present_data;
            for (row, (output, coefficients)) in parity
                .chunks_exact_mut(row_bytes)
                .zip(work.parity.chunks_exact(self.k))
                .enumerate()
            {
                match rows[self.k + row] {
                    Some(present) if selected_parity > 0 => {
                        output.copy_from_slice(present);
                        selected_parity -= 1;
                    }
                    _ => kernel::combine(
                        coefficients
                            .iter()
                            .copied()
                            .zip(data.chunks_exact(row_bytes)),
                        output,
                        backend,
                    ),
                }
            }
            for index in stripe * n..(stripe + 1) * n {
                let row = &codeword[self.chunk_range(index).ok_or(Rs16Error)?];
                if received[index].is_some_and(|received| received != row)
                    || !verify_original_row(index, row)
                {
                    return Err(Rs16Error);
                }
            }
            let offset = stripe * self.k * self.maximum_row;
            let remaining = (self.payload - offset).min(self.k * row_bytes);
            let data = &codeword[stripe_range.start..stripe_range.start + self.k * row_bytes];
            payload[offset..offset + remaining].copy_from_slice(&data[..remaining]);
            if data[remaining..].iter().any(|byte| *byte != 0) {
                return Err(Rs16Error);
            }
        }
        Ok(())
    }
}
/// Coefficient scratch carved from the front of the caller's workspace.
struct Work<'a> {
    matrix: &'a mut [u16],
    inverse: &'a mut [u16],
    parity: &'a mut [u16],
    indices: &'a mut [u16],
}
impl<'a> Work<'a> {
    fn new(shape: CompactShape, workspace: &'a mut [u16]) -> Self {
        let (matrix, rest) = workspace.split_at_mut(shape.k * shape.k);
        let (inverse, rest) = rest.split_at_mut(shape.k * shape.k);
        let (parity, rest) = rest.split_at_mut(shape.k * shape.m);
        Self {
            matrix,
            inverse,
            parity,
            indices: &mut rest[..shape.k],
        }
    }
}
/// Overwrite each parity row with its coefficient row applied to the stripe's data rows.
fn encode_parity_rows(
    k: usize,
    row_bytes: usize,
    coefficients: &[u16],
    data: &[u8],
    parity: &mut [u8],
    backend: Backend,
) {
    for (output, coefficients) in parity
        .chunks_exact_mut(row_bytes)
        .zip(coefficients.chunks_exact(k))
    {
        kernel::combine(
            coefficients
                .iter()
                .copied()
                .zip(data.chunks_exact(row_bytes)),
            output,
            backend,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::{host_backends, reference};
    use super::*;
    /// Recommended consensus layout: 4 data rows, 2 parity rows, 256 KiB maximum rows.
    const ROW: usize = 256 * 1024;
    const MIB: usize = 1024 * 1024;
    /// `(k, m, maximum row bytes, payload bytes, BLAKE3 of the complete codeword)`, pinned
    /// from the original log/exp and bit-serial SIMD kernels: stripe and row boundaries of the
    /// recommended layout, other protocol shapes, and the extreme 1+16 and 16+1 stripes.
    #[rustfmt::skip]
    const PINNED: &[(usize, usize, usize, usize, &str)] = &[
        (4, 2, ROW, 1, "ea9695e0dd2ca710f83820ebae79f3334e825b3056cf28dcf6db38b3e67a3edb"),
        (4, 2, ROW, 2, "fd8f9e99e0f63ed994c3ccb550ad32091d85d14b2a915375c69ba1bf28f6de4b"),
        (4, 2, ROW, 3, "7abf828827a33314cac1511f0e8e4db86ad384715af74fa6672c5484ed1219fd"),
        (4, 2, ROW, 7, "800ffff8160934ab9a86fd9e764558fd2a265269e3169d8e1e8033e49c1b8fd4"),
        (4, 2, ROW, 8, "63625d7a217619e7f203a3598b635e99966b0763618b49a1cdf2432e6e0917ce"),
        (4, 2, ROW, 9, "6117bf0073e9f8347c2ff57b5a981413c650a7f502d62b2167806ab73ca22808"),
        (4, 2, ROW, 17, "359fb476b127e8701190016f39b93bb94ec98acc72d79f02ca140a6cc608ec35"),
        (4, 2, ROW, 4095, "4e2765f39f4d108d6126afa1628e8965d12f98aa5299bdec998800e276a5976a"),
        (4, 2, ROW, 65536, "4f0018d9347ab4ff80cc804e905c235cebd6e32279351f851fa3c92c7d28d485"),
        (4, 2, ROW, ROW - 1, "0be7b9a0b5cf4f6781ddd9df75e39c14d24867a1625a4a266a5037b3e10ac92b"),
        (4, 2, ROW, MIB - 1, "46660f663c8f90215350133586b2f17cf3b0b6ea48bc9711f20ad48e0ea83286"),
        (4, 2, ROW, MIB, "f491cb1ef1af338be4712d95cba0cf027ca77656534f5815d3594f909300faa2"),
        (4, 2, ROW, MIB + 1, "b4b54f57d566b488c780015c796a3277e03f30dd13cc78a9faf0c330337ddd8c"),
        (4, 2, ROW, 2 * MIB + 12345, "5ca2fa4b1e36f63261852c7b7c70f4fee22b80077e4c6da838a17fe598148ba6"),
        (1, 1, 64, 1, "e5a8ac16dc288784ec830f7f6f2f40be19383cd333a0bdaf58d4a79f3ca2f844"),
        (1, 1, 64, 63, "f23672273e0c3263396273aa22c96d344057ebd658f79e5bebddc00611d10143"),
        (1, 1, 64, 64, "d890a22f14ac41878b29871364f8b1076e8ba476e69530e77ca5423459efa581"),
        (1, 1, 64, 65, "5284261c7f4e4e7c1f01611d893105f521238e5fb2c66c8959e211130532bb5d"),
        (1, 1, 64, 200, "9e12aceb4f272264d158ad9e62abb428de20943799ec21ad1e7a2f50d7caaca9"),
        (3, 3, 64, 5, "2eb73194efccd3a68af1050bfd2a6ae63f69c98a36ccacc80961b873b46b599d"),
        (3, 3, 64, 191, "4a86ce601b32f0cf2c74c9ad28c71d8b46579c8a4fe64dd8e7af968f09d3eae0"),
        (3, 3, 64, 192, "6dd57b5d059407dbf981c7e43b33ed29fd2da88c12f2eea24fbf336178cb7044"),
        (3, 3, 64, 193, "82352d1ba7da9e8bb881e3e7351cee2fea7722228daa1d58175b131edc743103"),
        (3, 3, 64, 1000, "c9b9d069ebaa13c3aa66657eac96950b838cb64e9cd4f121c31aca26bbfc17f8"),
        (16, 16, 64, 1, "dcee14e5565ef5d3f5feb8f240a3f0d1dbd9998a28483020905137af620386e9"),
        (16, 16, 64, 1023, "f652d7d0d9ebbad94457b8a04f04db3da168c75595d3f101737b44e2f8a02f6a"),
        (16, 16, 64, 1024, "d4a58c801d1275e4e85713d089494b25ac720e32abd03337a4fe400ab6a95a69"),
        (16, 16, 64, 1025, "59cda43b9cf2187645398b46f2527b3d3075d45c8376e5f06848c817c1c4fcff"),
        (16, 16, 64, 4093, "37032945bbcca192e427961827db387794e09dee9771d9a17f2009edf80aeff0"),
        (16, 16, ROW, 300_001, "48524f143ef3c281fd557242828301c1729b37c64db349137b9c58998fa082bb"),
        (5, 3, 1000, 4999, "bcec83efa1ddd6bc4957f5c56373bd50b3b54757ccdaa0f41a929ee2c06995c3"),
        (5, 3, 1000, 5001, "618b9ab34cd5827e3c2c6c7f591e645e7be03ff00e811b6f62503744cdbdbf5c"),
        (5, 3, 1000, 12345, "ca82a35618b1e6157606108dcefb70572b5b4f6f8988c7415bb55c45424f30da"),
        (7, 9, 30, 209, "a925f79f87fd55bbe765955665c28a51b07f2612163dd24f5ce95b015e15b0b5"),
        (7, 9, 30, 211, "a33fe52578ed27e371a60d15fee9ab085c512be8df4ebdd333e7e42425f3c30c"),
        (1, 16, 2, 1, "375cd42a94f40a643962cee5ea5e1fa41f61903e9ccde63fe33751c700fb47a0"),
        (1, 16, 2, 3, "4c11fbd645fc5586ca4535f838cbd002f96d678345e912c8e7075c77c20cf55c"),
        (1, 16, 2, 10, "394470a2b00c24a4d3b2846d3de038b6636af65b4aa4cd417ff6474c271e8da5"),
        (16, 1, 2, 31, "5e19b3f06f54e65e44731f7717edfb8029564db7f2a249d3f398be5a6c222047"),
        (16, 1, 2, 33, "8e13b25aa48e934d5bab963d6e88490ffa88d51b88223d0843f20e025135949c"),
        (16, 1, 2, 100, "f38d219132cc5d74536492df3d9041447b955d4181905a9737b4924f71d1933a"),
    ];
    fn pinned_payload(k: usize, m: usize, row: usize, len: usize) -> Vec<u8> {
        let seed = 0x9E37_79B9_7F4A_7C15_u64.wrapping_mul(len as u64 + 1)
            ^ (k * 1000 + m) as u64
            ^ (row as u64).rotate_left(32);
        reference::bytes(seed, len)
    }
    /// Every backend writes exactly the reference codeword, whose digest is pinned, over
    /// dirty output and scratch buffers.
    #[test]
    fn compact_codewords_match_reference_and_pinned_digests() {
        for &(k, m, row, len, expected) in PINNED {
            let payload = pinned_payload(k, m, row, len);
            let reference = reference::compact_encode(&payload, k, m, row);
            assert_eq!(
                reference::digest(&reference),
                expected,
                "reference {k}+{m} row {row} len {len}"
            );
            let shape = CompactShape::new(len, k, m, row).unwrap();
            assert_eq!(shape.encoded_bytes(), reference.len());
            let mut workspace = vec![0xA5A5; shape.workspace_words()];
            for backend in host_backends() {
                let mut codeword = vec![0xA5; shape.encoded_bytes()];
                shape
                    .encode_with_backend(&payload, &mut codeword, &mut workspace, backend)
                    .unwrap();
                assert!(
                    codeword == reference,
                    "{backend:?} {k}+{m} row {row} len {len}"
                );
            }
        }
    }
    /// Every pattern of at most m erasures per stripe (rotated across stripes) recovers the
    /// exact payload and codeword on every backend over dirty buffers; m+1 erasures reject.
    #[test]
    fn reconstruct_recovers_every_tolerated_erasure_pattern_on_every_backend() {
        for (k, m, row, lengths) in [
            (1, 1, 64, &[1usize, 64, 65, 129][..]),
            (4, 2, 64, &[1, 7, 255, 256, 257, 1000]),
            (3, 3, 30, &[1, 89, 90, 91, 400]),
            (2, 5, 16, &[1, 31, 32, 33, 100]),
        ] {
            let n = k + m;
            let patterns = (0u32..1 << n)
                .filter(|pattern| pattern.count_ones() as usize <= m)
                .collect::<Vec<_>>();
            for &len in lengths {
                let payload = pinned_payload(k, m, row, len);
                let shape = CompactShape::new(len, k, m, row).unwrap();
                let codeword = reference::compact_encode(&payload, k, m, row);
                let row_of = |index: usize| &codeword[shape.chunk_range(index).unwrap()];
                let mut workspace = vec![0x5A5A; shape.workspace_words()];
                for first in 0..patterns.len() {
                    let received = (0..shape.chunk_count())
                        .map(|index| {
                            let pattern = patterns[(first + index / n) % patterns.len()];
                            (pattern & (1 << (index % n)) == 0).then(|| row_of(index))
                        })
                        .collect::<Vec<_>>();
                    for backend in host_backends() {
                        let mut recovered = vec![0xA5; len];
                        let mut regenerated = vec![0xA5; shape.encoded_bytes()];
                        shape
                            .reconstruct_with_backend(
                                &received,
                                &mut recovered,
                                &mut regenerated,
                                &mut workspace,
                                |index, row| row == row_of(index),
                                backend,
                            )
                            .unwrap();
                        assert!(
                            recovered == payload && regenerated == codeword,
                            "{backend:?} {k}+{m} len {len} pattern {first}"
                        );
                    }
                }
                let received = (0..shape.chunk_count())
                    .map(|index| (index > m).then(|| row_of(index)))
                    .collect::<Vec<_>>();
                for backend in host_backends() {
                    let mut recovered = vec![0; len];
                    let mut regenerated = vec![0; shape.encoded_bytes()];
                    assert!(
                        shape
                            .reconstruct_with_backend(
                                &received,
                                &mut recovered,
                                &mut regenerated,
                                &mut workspace,
                                |_, _| true,
                                backend,
                            )
                            .is_err()
                    );
                }
            }
        }
    }
    /// The recommended layout decodes full 256 KiB rows: missing data rows, missing parity,
    /// and mixed erasures across a full and a terminal stripe.
    #[test]
    fn recommended_layout_reconstructs_full_rows_on_every_backend() {
        let len = MIB + 4097;
        let payload = pinned_payload(4, 2, ROW, len);
        let shape = CompactShape::new(len, 4, 2, ROW).unwrap();
        assert_eq!(shape.stripe_count(), 2);
        let codeword = reference::compact_encode(&payload, 4, 2, ROW);
        let mut workspace = vec![0; shape.workspace_words()];
        for missing in [[0, 1], [4, 5], [0, 5], [2, 3]] {
            let received = (0..shape.chunk_count())
                .map(|index| {
                    let local = index % 6;
                    let lost = if index < 6 {
                        missing.contains(&local)
                    } else {
                        local == (missing[0] + 1) % 6
                    };
                    (!lost).then(|| &codeword[shape.chunk_range(index).unwrap()])
                })
                .collect::<Vec<_>>();
            for backend in host_backends() {
                let mut recovered = vec![0xA5; len];
                let mut regenerated = vec![0xA5; shape.encoded_bytes()];
                shape
                    .reconstruct_with_backend(
                        &received,
                        &mut recovered,
                        &mut regenerated,
                        &mut workspace,
                        |index, row| row == &codeword[shape.chunk_range(index).unwrap()],
                        backend,
                    )
                    .unwrap();
                assert!(
                    recovered == payload && regenerated == codeword,
                    "{backend:?} missing {missing:?}"
                );
            }
        }
    }
    /// Geometry, buffer, row-length, row-count, consistency and commitment rejections.
    #[test]
    fn encode_and_reconstruct_reject_every_malformed_input_on_every_backend() {
        for invalid in [(0, 4, 2, 64), (1, 0, 2, 64), (1, 4, 0, 64), (1, 4, 2, 0)] {
            let (payload, k, m, row) = invalid;
            assert!(CompactShape::new(payload, k, m, row).is_err());
        }
        assert!(CompactShape::new(1, 4, 2, 63).is_err());
        assert!(CompactShape::new(1, 65_535, 1, 2).is_err());
        assert!(CompactShape::new(1, 65_534, 1, 2).is_ok());
        assert!(CompactShape::new(usize::MAX, 4, 2, usize::MAX - 1).is_err());
        let (k, m, row, len) = (4, 2, 64, 300);
        let payload = pinned_payload(k, m, row, len);
        let shape = CompactShape::new(len, k, m, row).unwrap();
        assert_eq!((shape.stripe_count(), shape.terminal_row_bytes()), (2, 12));
        let codeword = reference::compact_encode(&payload, k, m, row);
        let row_of = |index: usize| &codeword[shape.chunk_range(index).unwrap()];
        let all = (0..shape.chunk_count())
            .map(|index| Some(row_of(index)))
            .collect::<Vec<_>>();
        let words = shape.workspace_words();
        let encoded = codeword.len();
        for backend in host_backends() {
            for (payload_len, out_len, work_len) in [
                (len - 1, encoded, words),
                (len + 1, encoded, words),
                (len, encoded - 1, words),
                (len, encoded + 1, words),
                (len, encoded, words - 1),
            ] {
                let mut payload = payload.clone();
                payload.resize(payload_len, 0);
                let mut out = vec![0; out_len];
                let mut work = vec![0; work_len];
                assert!(
                    shape
                        .encode_with_backend(&payload, &mut out, &mut work, backend)
                        .is_err()
                );
            }
            let attempt = |received: &[Option<&[u8]>],
                           verify: &dyn Fn(usize, &[u8]) -> bool,
                           payload_len: usize,
                           out_len: usize,
                           work_len: usize| {
                let mut recovered = vec![0; payload_len];
                let mut regenerated = vec![0; out_len];
                let mut scratch = vec![0; work_len];
                shape
                    .reconstruct_with_backend(
                        received,
                        &mut recovered,
                        &mut regenerated,
                        &mut scratch,
                        |index, row| verify(index, row),
                        backend,
                    )
                    .map(|()| (recovered, regenerated))
            };
            let honest = |index: usize, row: &[u8]| row == row_of(index);
            assert_eq!(
                attempt(&all, &honest, len, encoded, words).unwrap(),
                (payload.clone(), codeword.clone())
            );
            assert!(attempt(&all[1..], &honest, len, encoded, words).is_err());
            assert!(attempt(&all, &honest, len - 1, encoded, words).is_err());
            assert!(attempt(&all, &honest, len, encoded + 1, words).is_err());
            assert!(attempt(&all, &honest, len, encoded, words - 1).is_err());
            let short = &row_of(7)[..row_of(7).len() - 2];
            let mut malformed = all.clone();
            malformed[7] = Some(short);
            assert!(attempt(&malformed, &honest, len, encoded, words).is_err());
            let mut sparse = all.clone();
            for index in [6, 8, 10] {
                sparse[index] = None;
            }
            assert!(attempt(&sparse, &honest, len, encoded, words).is_err());
            let mut tampered_parity = row_of(5).to_vec();
            tampered_parity[3] ^= 1;
            let mut inconsistent = all.clone();
            inconsistent[5] = Some(&tampered_parity);
            assert!(attempt(&inconsistent, &|_, _| true, len, encoded, words).is_err());
            let mut tampered_data = row_of(0).to_vec();
            tampered_data[0] ^= 0x80;
            let mut forged = all.clone();
            forged[0] = Some(&tampered_data);
            forged[4] = None;
            forged[5] = None;
            assert!(attempt(&forged, &honest, len, encoded, words).is_err());
            let mut missing = all.clone();
            missing[1] = None;
            missing[10] = None;
            assert!(attempt(&missing, &honest, len, encoded, words).is_ok());
            assert!(
                attempt(
                    &missing,
                    &|index, row| index != 10 && honest(index, row),
                    len,
                    encoded,
                    words
                )
                .is_err()
            );
        }
    }
    /// The compact codec and the owned-row API used by Torii and `SoraFS` agree on every stripe.
    #[test]
    fn compact_bytes_match_owned_row_parity_for_each_stripe() {
        for (k, m) in [(1, 1), (3, 3), (4, 2), (16, 16), (17, 2)] {
            for length in [1, 7, 8, 9, 63, 64, 65, 255, 256, 257, 4093] {
                let shape = CompactShape::new(length, k, m, 64).unwrap();
                let payload = (0..length)
                    .map(|i| u8::try_from(i.wrapping_mul(17) % 251).unwrap())
                    .collect::<Vec<_>>();
                let mut out = vec![0; shape.encoded_bytes()];
                let mut workspace = vec![0; shape.workspace_words()];
                shape
                    .encode_with_backend(&payload, &mut out, &mut workspace, Backend::Scalar)
                    .unwrap();
                for stripe in 0..shape.stripes {
                    let row_bytes = shape.row_bytes(stripe);
                    let data = (0..k)
                        .map(|row| {
                            let offset = (stripe * k * 64 + row * row_bytes).min(payload.len());
                            let end = (offset + row_bytes).min(payload.len());
                            super::super::symbols_from_chunk(row_bytes / 2, &payload[offset..end])
                        })
                        .collect::<Vec<_>>();
                    let parity = super::super::encode_parity(&data, m).unwrap();
                    for (row, symbols) in data.iter().chain(&parity).enumerate() {
                        let bytes = symbols
                            .iter()
                            .flat_map(|symbol| symbol.to_le_bytes())
                            .collect::<Vec<_>>();
                        assert_eq!(
                            &out[shape.chunk_range(stripe * (k + m) + row).unwrap()],
                            bytes.as_slice()
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn scalar_and_host_accelerated_boundaries_match_with_erasure_recovery() {
        let accelerated = choose_backend();
        eprintln!("compact host backend: {accelerated:?}");
        for (k, m) in [(1, 1), (4, 2), (16, 16)] {
            for length in [1, 7, 9, 63, 65, 255, 257, 4093, 23572] {
                let shape = CompactShape::new(length, k, m, 256 * 1024).unwrap();
                let original = (0..length)
                    .map(|i| u8::try_from(i % 251).unwrap())
                    .collect::<Vec<_>>();
                let mut scalar = vec![0; shape.encoded_bytes()];
                let mut host = scalar.clone();
                let mut work = vec![0; shape.workspace_words()];
                shape
                    .encode_with_backend(&original, &mut scalar, &mut work, Backend::Scalar)
                    .unwrap();
                shape
                    .encode_with_backend(&original, &mut host, &mut work, accelerated)
                    .unwrap();
                assert_eq!(scalar, host);
                let rows = (0..shape.chunk_count())
                    .map(|index| {
                        if index % (k + m) < m.min(k) {
                            None
                        } else {
                            Some(&scalar[shape.chunk_range(index).unwrap()])
                        }
                    })
                    .collect::<Vec<_>>();
                let mut payload = vec![0; length];
                let mut reconstructed = vec![0; shape.encoded_bytes()];
                for backend in [Backend::Scalar, accelerated] {
                    shape
                        .reconstruct_with_backend(
                            &rows,
                            &mut payload,
                            &mut reconstructed,
                            &mut work,
                            |i, row| row == &scalar[shape.chunk_range(i).unwrap()],
                            backend,
                        )
                        .unwrap();
                    assert_eq!(payload, original);
                    assert_eq!(reconstructed, scalar);
                }
            }
        }
    }
    #[test]
    fn consistent_nonzero_terminal_padding_rejects_even_with_matching_rows() {
        let longer = CompactShape::new(16, 4, 2, 64).unwrap();
        let target = CompactShape::new(9, 4, 2, 64).unwrap();
        assert_eq!(longer.encoded_bytes(), target.encoded_bytes());
        let payload = vec![1; 16];
        let mut codeword = vec![0; longer.encoded_bytes()];
        let mut work = vec![0; longer.workspace_words()];
        longer
            .encode_into(&payload, &mut codeword, &mut work)
            .unwrap();
        let rows = (0..target.chunk_count())
            .map(|i| Some(&codeword[target.chunk_range(i).unwrap()]))
            .collect::<Vec<_>>();
        let mut recovered = vec![0; 9];
        let mut regenerated = vec![0; target.encoded_bytes()];
        assert!(
            target
                .reconstruct_into(
                    &rows,
                    &mut recovered,
                    &mut regenerated,
                    &mut work,
                    |i, row| row == &codeword[target.chunk_range(i).unwrap()]
                )
                .is_err()
        );
    }
}
