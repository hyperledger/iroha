//! Canonical private quota-refresh witness retained by durable capsule custody.

use iroha_schema::IntoSchema;
use norito::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1, KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1,
    KAGEMUSHA_WALLET_VERSION_V1, KagemushaWalletQuotaUsageArrayV1, KagemushaWalletQuotaUsageLeafV1,
    WalletResult, WalletVersionsV1, decode_frame_v1, encode_frame_v1, invalid_v1,
    require_version_v1,
};

/// Complete predecessor quota usage for exactly one quota-share refresh.
///
/// A named retained-input role selects this type; bytes are never identified by
/// length. All 64 ordered slots are retained before Advance selects the new head,
/// including explicit trailing padding. The transition owner authenticates the
/// recomputed root against its actual predecessor before rebuilding usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaRefreshWitnessV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletQuotaRefreshWitnessV1 {
    /// First-release wire version, exactly 1.
    pub version: u16,
    /// Exactly 64 predecessor usage leaves in slot order; `None` is the unique padding leaf.
    pub predecessor_usage:
        [Option<KagemushaWalletQuotaUsageLeafV1>; KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1],
}

impl KagemushaWalletQuotaRefreshWitnessV1 {
    /// Retain an existing native usage array without changing its slots.
    ///
    /// # Errors
    /// Invalid occupied order, window interval or padding.
    pub fn from_usage(usage: &KagemushaWalletQuotaUsageArrayV1) -> WalletResult<Self> {
        let witness = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            predecessor_usage: *usage.slots(),
        };
        witness.validate()?;
        Ok(witness)
    }

    /// Validate the fixed array and return its exact native representation.
    /// This does not authenticate any predecessor root or approve a policy update.
    ///
    /// # Errors
    /// Unsupported version, a hole, duplicate/reordered key, empty/inverted window,
    /// or overlapping windows of the same kind.
    pub fn usage(&self) -> WalletResult<KagemushaWalletQuotaUsageArrayV1> {
        self.validate()?;
        KagemushaWalletQuotaUsageArrayV1::from_slots(self.predecessor_usage)
    }

    /// Validate canonical fixed 64-slot semantics, without granting root authority.
    ///
    /// # Errors
    /// Unsupported version or malformed slot order, intervals or padding.
    pub fn validate(&self) -> WalletResult<()> {
        self.require_versions()?;
        KagemushaWalletQuotaUsageArrayV1::from_slots(self.predecessor_usage)?;
        let mut previous: Option<&KagemushaWalletQuotaUsageLeafV1> = None;
        for leaf in self.predecessor_usage.iter().flatten() {
            if leaf.window_start_ms >= leaf.window_end_ms {
                return Err(invalid_v1("quota_refresh_witness.interval"));
            }
            if previous.is_some_and(|old| {
                let previous_key = (old.window_kind, old.window_start_ms);
                let current_key = (leaf.window_kind, leaf.window_start_ms);
                let same_kind = old.window_kind == leaf.window_kind;
                let overlaps_previous = leaf.window_start_ms < old.window_end_ms;
                previous_key >= current_key || (same_kind && overlaps_previous)
            }) {
                return Err(invalid_v1("quota_refresh_witness.order"));
            }
            previous = Some(leaf);
        }
        Ok(())
    }

    /// Encode one bounded canonical Norito frame after shape validation.
    ///
    /// # Errors
    /// Invalid witness, encoding failure or frame exceeding 8,192 bytes.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1)
    }

    /// Decode exactly one bounded canonical 64-slot witness frame.
    ///
    /// # Errors
    /// Oversized, truncated, noncanonical or trailing bytes, wrong version or shape.
    pub fn decode_canonical(bytes: &[u8]) -> WalletResult<Self> {
        let value: Self =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1)?;
        value.validate()?;
        Ok(value)
    }
}

impl WalletVersionsV1 for KagemushaWalletQuotaRefreshWitnessV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("quota_refresh_witness.version", self.version)
    }
}

#[cfg(test)]
#[path = "quota_custody_tests.rs"]
mod tests;
