//! Untrusted native finality transport records (`specs/sccp.md` §6).
//!
//! Decoding these records grants no finality authority. Readers verify the certificate against
//! their independently authenticated consensus instance and committee generation. The canonical
//! contract layouts remain fixed byte strings, not Norito encodings of their parsed fields.

use super::committee::{
    SccpCommitteeGenerationV1, SccpGenerationCauseV1, SccpGenerationEndV1, SccpGenerationMemberV1,
};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

macro_rules! record {
    ($(#[$meta:meta])* pub struct $name:ident { $($fields:tt)* }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, IntoSchema,
            DeriveJsonSerialize, DeriveJsonDeserialize, norito::NoritoSchema)]
        #[norito(no_fast_from_json)]
        #[norito(decode_from_slice)]
        #[norito(deny_unknown_fields)]
        $(#[$meta])*
        pub struct $name { $($fields)* }
    };
}

record! {
    /// Exact native CommitQC projection and its untrusted committee claim.
    #[norito_schema(name = "iroha_data_model::sccp::finality::SccpCertificateV1")]
    pub struct SccpCertificateV1 {
        /// Certified height; must equal the height inside `header`.
        pub height: u64,
        /// Canonical `QC_FIXED` (§3.7), with a big-endian signer word.
        pub qc: [u8; 116],
        /// Compressed BLS-normal G2 aggregate over exactly `n - f` votes.
        pub aggregate_signature: [u8; 96],
        /// Canonical finality header `X` (§3.6).
        pub header: [u8; 221],
        /// Canonically ordered compressed G1 keys; these do not authenticate themselves.
        pub committee: Vec<[u8; 48]>,
    }
}

record! {
    /// The block containing a message, with its optional path to a later certified history.
    #[norito_schema(name = "iroha_data_model::sccp::finality::SccpBlockRefV1")]
    pub struct SccpBlockRefV1 {
        /// Height at which the leaf was recorded.
        pub height: u64,
        /// Root of that block's ordered SCCP leaves.
        pub sccp_root: [u8; 32],
        /// Number of leaves in that block.
        pub message_count: u32,
        /// History leaf index; zero for a direct proof.
        pub history_index: u64,
        /// History path; empty for a direct proof.
        pub history_path: Vec<[u8; 32]>,
    }
}

record! {
    /// A certified rotation and the exact ordered keys of its successor.
    #[norito_schema(name = "iroha_data_model::sccp::finality::SccpRotationV1")]
    pub struct SccpRotationV1 {
        /// Native certificate whose header carries `ROTATION`.
        pub certificate: SccpCertificateV1,
        /// Successor keys, committed by the header's `next_committee_root`.
        pub next_committee: Vec<[u8; 48]>,
    }
}

record! {
    /// A retained generation and its liability at the same committed read cut.
    #[norito_schema(name = "iroha_data_model::sccp::finality::SccpGenerationV1")]
    pub struct SccpGenerationV1 {
        /// Monotonic SCCP generation, starting at one (distinct from native epoch numbering).
        pub generation: u64,
        /// Canonical Keccak committee root over `keys`.
        pub committee_root: [u8; 32],
        /// Strictly ascending compressed subgroup BLS-normal keys, exactly `3f + 1`.
        pub keys: Vec<[u8; 48]>,
        /// Tenure at each key's bitmap index; unresolved keys remain explicitly `None`.
        pub members: Vec<Option<SccpGenerationMemberV1>>,
        /// Creation trigger.
        pub cause: SccpGenerationCauseV1,
        /// First height signed by this generation.
        pub start_height: u64,
        /// Genesis/handoff/resync time that starts its destination trust window.
        pub start_timestamp_ms: u64,
        /// Liability clock at creation.
        pub start_lc: u64,
        /// Creation-time validity; later parameter changes cannot renew it.
        pub validity_ms: u64,
        /// Exactly `start_timestamp_ms + validity_ms`.
        pub deadline_ms: u64,
        /// Creation-time evidence grace.
        pub grace_ms: u64,
        /// Creation-time maximum additional destination-progress wait.
        pub progress_cap_ms: u64,
        /// Exactly `start_lc + validity_ms + grace_ms`.
        pub liable_until_lc: u64,
        /// Liability clock when all relevant destination chains passed this deadline.
        #[norito(required)]
        pub dest_cleared_lc: Option<u64>,
        /// Absent for the current generation until it ends.
        #[norito(required)]
        pub end: Option<SccpGenerationEndV1>,
        /// Liability evaluated at the same committed generation/clock cut.
        pub liable: bool,
    }
}

impl SccpGenerationV1 {
    /// Project a retained record and evaluate its liability at one committed read cut.
    #[must_use]
    pub fn from_record(
        record: &SccpCommitteeGenerationV1,
        current_generation: u64,
        liability_clock: u64,
    ) -> Self {
        let liable = record.liable_at(current_generation, liability_clock);
        let SccpCommitteeGenerationV1 {
            generation,
            committee_root,
            keys,
            members,
            cause,
            start_height,
            start_timestamp_ms,
            start_lc,
            validity_ms,
            deadline_ms,
            grace_ms,
            progress_cap_ms,
            liable_until_lc,
            dest_cleared_lc,
            end,
        } = record.clone();
        Self {
            generation,
            committee_root,
            keys,
            members,
            cause,
            start_height,
            start_timestamp_ms,
            start_lc,
            validity_ms,
            deadline_ms,
            grace_ms,
            progress_cap_ms,
            liable_until_lc,
            dest_cleared_lc,
            end,
            liable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};

    #[test]
    fn certificate_and_block_transport_roundtrip_without_granting_authority() {
        // Deliberately invalid cryptographic claims still roundtrip as transport. Verification
        // belongs above this layer and must never be inferred from successful decoding.
        let certificate = SccpCertificateV1 {
            height: 7,
            qc: [1; 116],
            aggregate_signature: [2; 96],
            header: [3; 221],
            committee: vec![[4; 48]; 4],
        };
        roundtrip(&certificate);
        assert_rejects_unknown_field(&certificate, &[]);
        let block = SccpBlockRefV1 {
            height: 5,
            sccp_root: [6; 32],
            message_count: 3,
            history_index: 2,
            history_path: vec![[7; 32]; 2],
        };
        roundtrip(&block);
        assert_rejects_unknown_field(&block, &[]);
        let rotation = SccpRotationV1 {
            certificate,
            next_committee: vec![[8; 48]; 7],
        };
        roundtrip(&rotation);
        assert_rejects_unknown_field(&rotation, &[]);
    }

    #[test]
    fn generation_projection_is_flat_and_uses_the_same_liability_cut() {
        let record = SccpCommitteeGenerationV1 {
            generation: 1,
            committee_root: [1; 32],
            keys: vec![[2; 48]; 4],
            members: vec![None; 4],
            cause: SccpGenerationCauseV1::Genesis,
            start_height: 1,
            start_timestamp_ms: 100,
            start_lc: 100,
            validity_ms: 10,
            deadline_ms: 110,
            grace_ms: 20,
            progress_cap_ms: 5,
            liable_until_lc: 130,
            dest_cleared_lc: None,
            end: None,
        };
        let current = SccpGenerationV1::from_record(&record, 1, 999);
        assert!(current.liable);
        let historical = SccpGenerationV1::from_record(&record, 2, 136);
        assert!(!historical.liable);
        assert!(SccpGenerationV1::from_record(&record, 2, 135).liable);
        assert_eq!(historical.keys, record.keys);
        assert_eq!(historical.members, record.members);
        assert_eq!(historical.deadline_ms, record.deadline_ms);
        roundtrip(&historical);
        assert_rejects_unknown_field(&historical, &[]);
        let mut value = norito::json::to_value(&historical).unwrap();
        assert!(value.get("record").is_none());
        assert_eq!(
            value
                .get("generation")
                .and_then(norito::json::Value::as_u64),
            Some(1)
        );
        value.as_object_mut().unwrap().remove("end");
        assert!(norito::json::from_value::<SccpGenerationV1>(value).is_err());
    }
}
