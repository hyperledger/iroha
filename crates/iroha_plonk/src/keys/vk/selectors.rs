//! Borrowed selector activations in a strictly admitted canonical VK encoding.

use iroha_pasta::{CancellationToken, Cancelled};

/// Check the complete packed suffix without allocating one byte per row.
/// The VK reader independently requires its exact descriptor-derived extent.
pub(super) fn validate_cancellable(
    bytes: &[u8],
    rows: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(), super::VkError> {
    CancellationToken::checkpoint(cancellation)?;
    let width = rows.div_ceil(8);
    if width == 0 || !bytes.len().is_multiple_of(width) {
        return Err(super::VkError::Shape);
    }
    for (selector, chunk) in bytes.chunks_exact(width).enumerate() {
        CancellationToken::checkpoint(cancellation)?;
        if !rows.is_multiple_of(8) && chunk[width - 1] >> (rows % 8) != 0 {
            return Err(super::VkError::BitmapPadding { selector });
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(())
}

/// Independent expanded reference for packed admission tests.
#[cfg(test)]
pub(super) fn decode_cancellable(
    bytes: &[u8],
    rows: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Vec<bool>>, super::VkError> {
    let mut selectors = Vec::new();
    for (selector, chunk) in bytes.chunks(rows.div_ceil(8)).enumerate() {
        let mut activations = Vec::with_capacity(rows);
        for (byte_index, byte) in chunk.iter().enumerate() {
            if byte_index % 512 == 0 {
                CancellationToken::checkpoint(cancellation)?;
            }
            for bit in 0..8 {
                let row = 8 * byte_index + bit;
                let active = (byte >> bit) & 1 == 1;
                if row < rows {
                    activations.push(active);
                } else if active {
                    return Err(super::VkError::BitmapPadding { selector });
                }
            }
        }
        selectors.push(activations);
    }
    Ok(selectors)
}

/// Selector activations borrowed directly from a verifying key's canonical bytes.
///
/// Creating this view does not confer source authority: original-key admission
/// still compares every activation with the independently synthesized circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorBitmaps<'a> {
    bytes: &'a [u8],
    rows: usize,
}

impl<'a> SelectorBitmaps<'a> {
    /// Only the strict VK reader/constructor may supply the validated suffix.
    pub(super) fn new(bytes: &'a [u8], rows: usize) -> Self {
        Self { bytes, rows }
    }

    /// The number of selector activation bitmaps.
    #[must_use]
    pub fn len(self) -> usize {
        self.bytes.len() / self.rows.div_ceil(8)
    }

    /// Whether the verifying key carries no selector activation bitmaps.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow a selector by its descriptor index.
    #[must_use]
    pub fn get(self, selector: usize) -> Option<SelectorBitmap<'a>> {
        if selector >= self.len() {
            return None;
        }
        let width = self.rows.div_ceil(8);
        Some(SelectorBitmap {
            bytes: &self.bytes[selector * width..(selector + 1) * width],
            rows: self.rows,
        })
    }

    /// Borrow selectors in descriptor order without expanding their row bits.
    pub fn iter(self) -> impl ExactSizeIterator<Item = SelectorBitmap<'a>> + DoubleEndedIterator {
        self.bytes
            .chunks_exact(self.rows.div_ceil(8))
            .map(move |bytes| SelectorBitmap {
                bytes,
                rows: self.rows,
            })
    }

    /// Compare every native activation with the admitted VK without allocation.
    pub(in crate::keys) fn matches_rows_cancellable(
        self,
        expanded: &[Vec<bool>],
        cancellation: Option<&CancellationToken>,
    ) -> Result<bool, Cancelled> {
        CancellationToken::checkpoint(cancellation)?;
        if expanded.len() != self.len() {
            return Ok(false);
        }
        for (native, packed) in expanded.iter().zip(self.iter()) {
            if native.len() != self.rows {
                return Ok(false);
            }
            for (index, (chunk, expected)) in native.chunks(8).zip(packed.bytes).enumerate() {
                if index % 128 == 0 {
                    CancellationToken::checkpoint(cancellation)?;
                }
                let actual = chunk.iter().enumerate().fold(0_u8, |byte, (bit, enabled)| {
                    byte | (u8::from(*enabled) << bit)
                });
                if actual != *expected {
                    return Ok(false);
                }
            }
        }
        CancellationToken::checkpoint(cancellation)?;
        Ok(true)
    }
}

/// One selector's row activations borrowed from a strictly admitted verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorBitmap<'a> {
    bytes: &'a [u8],
    rows: usize,
}

impl<'a> SelectorBitmap<'a> {
    /// The number of rows, excluding the encoding's zero padding bits.
    #[must_use]
    pub fn len(self) -> usize {
        self.rows
    }

    /// Whether this bitmap has no rows.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.rows == 0
    }

    /// Read one row activation, or `None` beyond the circuit domain.
    #[must_use]
    pub fn get(self, row: usize) -> Option<bool> {
        (row < self.rows).then(|| self.bytes[row / 8] & (1 << (row % 8)) != 0)
    }

    /// Read row activations in order without allocating an expanded bitmap.
    pub fn iter(self) -> impl ExactSizeIterator<Item = bool> + DoubleEndedIterator {
        (0..self.rows).map(move |row| self.bytes[row / 8] & (1 << (row % 8)) != 0)
    }

    /// Canonical low-bit-first bytes, including only validated zero padding.
    pub(in crate::keys) fn packed_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests;
