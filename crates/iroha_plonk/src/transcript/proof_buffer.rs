//! An owned proof buffer that clears retired allocations before releasing them.
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub(super) struct ProofBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

impl ProofBuffer {
    pub(super) fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn append(&mut self, bytes: &[u8]) {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .expect("proof length fits memory");
        if required > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .max(32);
            let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
            replacement.extend_from_slice(&self.bytes);
            // No realloc may free the previous private proof bytes first.
            self.bytes.zeroize();
            self.bytes = replacement;
        }
        self.bytes.extend_from_slice(bytes);
    }

    pub(super) fn finish(mut self) -> Vec<u8> {
        // Explicit transfer to the caller. Private callers must retain a clearing
        // owner; an unfinished writer always retains the guarded allocation.
        core::mem::take(&mut *self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_clone_and_explicit_transfer_preserve_exact_bytes() {
        let mut buffer = ProofBuffer::new();
        let mut expected = Vec::new();
        for length in [0, 1, 31, 32, 33, 511, 2048, 4097] {
            let message = vec![(length % 251) as u8; length];
            buffer.append(&message);
            expected.extend_from_slice(&message);
            assert_eq!(buffer.as_slice(), expected);
            assert_eq!(buffer.clone().finish(), expected);
        }
        assert_eq!(buffer.finish(), expected);
    }
}
