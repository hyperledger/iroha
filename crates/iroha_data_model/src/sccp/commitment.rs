//! SCCP v1 block commitments and the history accumulator (`specs/sccp.md` §3.4, §3.5, §4.5).
//!
//! Every SCCP-bearing block stores the root of its commitment tree and its history leaf index;
//! the accumulator keeps the peaks from which `history_root(size)` is computed. The roots are
//! contract-visible and are computed by `iroha_sccp::v1` from these fields.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Largest history size a verifier accepts (`history_size ≤ 2^32`, §3.5).
pub const SCCP_HISTORY_MAX_SIZE_V1: u64 = 1 << 32;

/// Commitment of one SCCP-bearing block (`sccp_block_commitments[height]`, §4.5).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::commitment::SccpBlockCommitmentV1")]
pub struct SccpBlockCommitmentV1 {
    /// §3.4 promote-odd root over the block's leaves.
    pub root: [u8; 32],
    /// Number of leaves, `1..=512`.
    pub message_count: u32,
    /// 0-based index of the block's history leaf (§3.5).
    pub history_index: u64,
}

/// History accumulator state: size and perfect-subtree peaks, largest first (§3.5).
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::commitment::SccpHistoryStateV1")]
pub struct SccpHistoryStateV1 {
    /// Number of history leaves.
    pub size: u64,
    /// Roots of the perfect subtrees of the binary decomposition of `size`, largest first.
    pub peaks: Vec<[u8; 32]>,
}

impl SccpHistoryStateV1 {
    /// Return whether the peak count matches `size` and `size ≤ 2^32`.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.size <= SCCP_HISTORY_MAX_SIZE_V1
            && u32::try_from(self.peaks.len()).is_ok_and(|len| len == self.size.count_ones())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};

    #[test]
    fn constants_match_the_spec() {
        assert_eq!(SCCP_HISTORY_MAX_SIZE_V1, 4_294_967_296);
        assert_eq!(
            SCCP_HISTORY_MAX_SIZE_V1,
            crate::sumeragi_finality::certified_result::MAX_HISTORY_SIZE,
            "the accumulator bound is the bound the finality header enforces"
        );
    }

    #[test]
    fn binary_and_json_roundtrip() {
        let commitment = SccpBlockCommitmentV1 {
            root: [4; 32],
            message_count: 512,
            history_index: 9,
        };
        roundtrip(&commitment);
        roundtrip(&SccpHistoryStateV1::default());
        let history = SccpHistoryStateV1 {
            size: 3,
            peaks: vec![[5; 32], [6; 32]],
        };
        roundtrip(&history);
        assert_rejects_unknown_field(&commitment, &[]);
        assert_rejects_unknown_field(&history, &[]);
    }

    #[test]
    fn history_peaks_follow_the_binary_decomposition() {
        assert!(SccpHistoryStateV1::default().is_well_formed());
        let state = |size, peaks: usize| SccpHistoryStateV1 {
            size,
            peaks: vec![[1; 32]; peaks],
        };
        assert!(state(1, 1).is_well_formed());
        assert!(state(6, 2).is_well_formed());
        assert!(state(7, 3).is_well_formed());
        assert!(!state(7, 2).is_well_formed());
        assert!(!state(0, 1).is_well_formed());
        assert!(state(SCCP_HISTORY_MAX_SIZE_V1, 1).is_well_formed());
        assert!(!state(SCCP_HISTORY_MAX_SIZE_V1 + 1, 2).is_well_formed());
    }
}
