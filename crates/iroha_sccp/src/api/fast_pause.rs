//! Committed fast-pause observations and bounded original anchor witnesses.

use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    sccp::{
        fast_pause::{SccpFastPauseRoundV1, SccpFastPauseV1, SccpPanelRoleV1, SccpPausePanelV1},
        native::SccpAnchorWitnessV1,
    },
};
use norito::codec::{Decode, Encode};

macro_rules! record {
    ($(#[$meta:meta])* pub struct $name:ident { $($body:tt)* }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, norito::derive::JsonSerialize, norito::derive::JsonDeserialize, norito::NoritoSchema)]
        #[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
        $(#[$meta])*
        pub struct $name { $($body)* }
    };
}

record! {
    /// Current seats, derived only when the authoritative eligibility source is available.
    #[norito_schema(name = "iroha_sccp::api::SccpPauseSeatsV1")]
    pub struct SccpPauseSeatsV1 {
        /// Primary panel in canonical seat order, at most nine accounts.
        pub primary: Vec<AccountId>,
        /// Backup panel in canonical seat order, at most nine accounts.
        pub backup: Vec<AccountId>,
    }
}
record! {
    /// A retained current endorsement round for one network and panel role.
    #[norito_schema(name = "iroha_sccp::api::SccpFastPauseRoundViewV1")]
    pub struct SccpFastPauseRoundViewV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Primary or backup panel.
        pub role: SccpPanelRoleV1,
        /// Exact committed round.
        pub round: SccpFastPauseRoundV1,
    }
}
record! {
    /// A retained pause, whose time and independent scope bits determine its effects.
    #[norito_schema(name = "iroha_sccp::api::SccpFastPauseActiveViewV1")]
    pub struct SccpFastPauseActiveViewV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Exact committed hold parts and deadline.
        pub pause: SccpFastPauseV1,
    }
}
record! {
    /// A committed suspension of new emergency certification on one network.
    #[norito_schema(name = "iroha_sccp::api::SccpFastPauseSuspendedViewV1")]
    #[derive(Copy)]
    pub struct SccpFastPauseSuspendedViewV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Absolute suspension deadline.
        pub until_ms: u64,
    }
}
record! {
    /// Source-bound fast-pause DATA; it conveys no Parliament or execution authority.
    #[norito_schema(name = "iroha_sccp::api::SccpFastPauseViewV1")]
    pub struct SccpFastPauseViewV1 {
        /// Original standing draw and recorded acceptances, when one exists.
        #[norito(required)]
        pub panel: Option<SccpPausePanelV1>,
        /// Derived seats, absent when no panel exists or eligibility cannot be read.
        #[norito(required)]
        pub seats: Option<SccpPauseSeatsV1>,
        /// Whether the canonical Parliament eligibility source can derive seats now.
        pub eligibility_available: bool,
        /// At most six original rounds: three networks times two roles.
        pub rounds: Vec<SccpFastPauseRoundViewV1>,
        /// At most three retained per-network pause records, including expired records.
        pub active: Vec<SccpFastPauseActiveViewV1>,
        /// At most three retained per-network suspension deadlines.
        pub suspended: Vec<SccpFastPauseSuspendedViewV1>,
    }
}
record! {
    /// Original anchor witness against a retained completed root.
    #[norito_schema(name = "iroha_sccp::api::SccpAnchorWitnessBundleV1")]
    #[derive(Copy)]
    pub struct SccpAnchorWitnessBundleV1 {
        /// Requested nonzero committed height.
        pub height: u64,
        /// Zero-based 4096-height chunk.
        pub chunk: u64,
        /// Absent at the committed tip or in its open chunk, where Core reads original anchors.
        #[norito(required)]
        pub witness: Option<SccpAnchorWitnessV1>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_seats_are_explicit_and_wire_roundtrips_keep_anchor_identity() {
        let view = SccpFastPauseViewV1 {
            panel: None,
            seats: None,
            eligibility_available: false,
            rounds: Vec::new(),
            active: Vec::new(),
            suspended: Vec::new(),
        };
        let json = norito::json::to_json(&view).unwrap();
        assert!(json.contains("\"eligibility_available\":false"));
        assert_eq!(
            norito::json::from_json::<SccpFastPauseViewV1>(&json).unwrap(),
            view
        );
        assert_eq!(
            norito::decode_from_bytes::<SccpFastPauseViewV1>(&norito::to_bytes(&view).unwrap())
                .unwrap(),
            view
        );
        let bundle = SccpAnchorWitnessBundleV1 {
            height: 17,
            chunk: 0,
            witness: Some(SccpAnchorWitnessV1 {
                core_hash: [1; 32],
                result: [2; 32],
                path: [[3; 32]; 12],
            }),
        };
        assert_eq!(
            norito::decode_from_bytes::<SccpAnchorWitnessBundleV1>(
                &norito::to_bytes(&bundle).unwrap()
            )
            .unwrap(),
            bundle
        );
        assert_eq!(
            norito::json::from_json::<SccpAnchorWitnessBundleV1>(
                &norito::json::to_json(&bundle).unwrap()
            )
            .unwrap(),
            bundle
        );
    }
}
