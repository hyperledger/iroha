//! Typed entry points for the sole shared fixed-V1 counted transaction writer.

use super::{
    SignedTransaction, TransactionEntrypoint,
    wire_v1::{
        SIGNED_TRANSACTION_FRAME_OVERHEAD_BYTES_V1, SIGNED_TRANSACTION_WIRE_PREFIX_BYTES_V1,
        WireV1Plan,
    },
};

impl SignedTransaction {
    /// Convert a complete fixed-V1 signed wire extent to its canonical frame extent.
    ///
    /// This is size geometry only: it does not validate bytes, signatures, resource
    /// admission or authority. The sole writer owns the one-byte prefix and checked
    /// zero-padding type invariant. No entrypoint or payload-only extent may be used.
    /// Returns `None` for a missing prefix or arithmetic overflow.
    #[must_use]
    pub const fn canonical_frame_len_from_wire_len_v1(wire_bytes: usize) -> Option<usize> {
        if wire_bytes < SIGNED_TRANSACTION_WIRE_PREFIX_BYTES_V1 {
            return None;
        }
        wire_bytes.checked_add(SIGNED_TRANSACTION_FRAME_OVERHEAD_BYTES_V1)
    }

    /// Measure the exact original signed transaction for a caller-owned output destination.
    ///
    /// The returned plan borrows this transaction. Its extent does not account for serializer
    /// scratch, and it grants no custody, signature or submission authority.
    ///
    /// # Errors
    /// Returns the original serialization error from the real counting pass.
    pub fn wire_plan_v1(&self) -> Result<WireV1Plan<'_>, norito::Error> {
        WireV1Plan::new(self)
    }
}

impl TransactionEntrypoint {
    /// Measure the exact V1 entrypoint, retaining its variant and complete signed authorization.
    ///
    /// This is the versioned entrypoint wire, distinct from both `SignedTransaction`'s wire and
    /// a header-framed native entrypoint. Its extent does not fund serializer scratch.
    ///
    /// # Errors
    /// Returns the original serialization error from the real counting pass.
    pub fn wire_plan_v1(&self) -> Result<WireV1Plan<'_>, norito::Error> {
        WireV1Plan::new(self)
    }
}
