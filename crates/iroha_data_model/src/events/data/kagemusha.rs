//! System events emitted by successful ordinary KAGEMUSHA wallet execution.

use crate::{
    Decode, Encode, isi::kagemusha_wallet::load_finality::KagemushaWalletLoadReceiptV1,
    kagemusha::KagemushaWalletValidationErrorV1,
};

/// Successful ledger execution of an ordinary Load.
///
/// Core emits this event only when `IssueLoad` creates the original receipt.
/// Its digest commits the complete validated 282-byte receipt transcript,
/// including the original transaction, height and canonical payer identity.
/// This record is not a finality claim: authenticate its exact ordered event
/// inclusion against a native certified execution result before accepting it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::events::data::kagemusha::KagemushaLoadCommittedV1")]
pub struct KagemushaLoadCommittedV1 {
    /// Canonical sigma-field Poseidon identity of the original Load receipt.
    pub receipt_digest: [u8; 32],
}

impl KagemushaLoadCommittedV1 {
    /// Construct the system event from a structurally valid original receipt.
    /// This computes an identity only; it confers no execution or finality authority.
    ///
    /// # Errors
    /// The receipt or its canonical payer identity is invalid.
    pub fn from_receipt(
        receipt: &KagemushaWalletLoadReceiptV1,
    ) -> Result<Self, KagemushaWalletValidationErrorV1> {
        Ok(Self {
            receipt_digest: receipt.receipt_digest()?,
        })
    }
}

impl_json_via_norito_bytes!(KagemushaLoadCommittedV1);

#[cfg(test)]
mod tests;
