//! SCCP v1 route registry state (`specs/sccp.md` §2.3, §4.14.1, §4.14.2).
//!
//! Each external network has one route (`taira_eth_xor`, `taira_bsc_xor`, `taira_ton_xor`) with
//! one escrow account and a map of revisions. Each revision binds one destination deployment and
//! carries its own liability, nonces and activation state.

use super::{
    control::SCCP_FIRST_CONTROL_NONCE_V1,
    deployment::{SccpCommitteePinV1, SccpDeploymentV1},
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, bridge::SccpNetworkV1,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::BTreeMap;

/// Route id of Taira XOR on Ethereum.
pub const SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1: &str = "taira_eth_xor";
/// Route id of Taira XOR on BSC.
pub const SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1: &str = "taira_bsc_xor";
/// Route id of Taira XOR on TON.
pub const SCCP_ROUTE_ID_TAIRA_TON_XOR_V1: &str = "taira_ton_xor";

/// Return the route id of `network`, or `None` for `sora-taira`.
#[must_use]
pub const fn route_id_for(network: SccpNetworkV1) -> Option<&'static str> {
    match network {
        SccpNetworkV1::SoraTaira => None,
        SccpNetworkV1::EthereumMainnet => Some(SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1),
        SccpNetworkV1::BscMainnet => Some(SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1),
        SccpNetworkV1::TonMainnet => Some(SCCP_ROUTE_ID_TAIRA_TON_XOR_V1),
    }
}

/// The three external networks with a route, in registry order (§2.3, §4.14.1).
pub const SCCP_ROUTE_NETWORKS_V1: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

/// Activation state of one route revision (§4.14.2).
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
#[norito(tag = "activation", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::registry::SccpRouteActivationV1")]
pub enum SccpRouteActivationV1 {
    /// Registered, not yet activated.
    #[codec(index = 0)]
    #[norito(rename = "staged")]
    Staged,
    /// Records outbound messages and settles inbound ones.
    #[codec(index = 1)]
    #[norito(rename = "bidirectional")]
    Bidirectional,
    /// Taira-side pause: no records; settlements and refunds held `Pending`.
    #[codec(index = 2)]
    #[norito(rename = "paused")]
    Paused,
    /// Drains: proofs, settlements, voids and refunds, but no new records.
    #[codec(index = 3)]
    #[norito(rename = "inbound_only")]
    InboundOnly,
    /// Terminal; requires zero liability and nothing pending.
    #[codec(index = 4)]
    #[norito(rename = "retired")]
    Retired,
}

impl SccpRouteActivationV1 {
    /// Return whether inbound settlement and outbound refunds proceed (else held `Pending`).
    #[must_use]
    pub const fn settles(self) -> bool {
        matches!(self, Self::Bidirectional | Self::InboundOnly)
    }

    /// Return whether the revision is live: `Bidirectional` or `Paused` (at most one per route).
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Bidirectional | Self::Paused)
    }

    /// Return whether `self → to` is a §4.14.2 transition.
    ///
    /// `Staged → Bidirectional`, `Bidirectional ⇄ Paused`, `Bidirectional | Paused →
    /// InboundOnly` and `InboundOnly → Retired`.
    #[must_use]
    pub const fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Staged | Self::Paused, Self::Bidirectional)
                | (Self::Bidirectional, Self::Paused)
                | (Self::Bidirectional | Self::Paused, Self::InboundOnly)
                | (Self::InboundOnly, Self::Retired)
        )
    }
}

/// One route revision (§4.14.1).
///
/// Each revision retains the exact immutable committee pin checked at registration. The pin
/// is data, not standalone authority: current generation/finality verification remains required.
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
#[norito_schema(name = "iroha_data_model::sccp::registry::SccpRouteRevisionV1")]
pub struct SccpRouteRevisionV1 {
    /// Revision number, starting at 1.
    pub revision: u32,
    /// Bound destination deployment.
    pub deployment: SccpDeploymentV1,
    /// Original committee pin of the destination deployment.
    pub initial_committee: SccpCommitteePinV1,
    /// §3.4 destination word of the deployment.
    pub destination_word: [u8; 32],
    /// Activation state.
    pub activation: SccpRouteActivationV1,
    /// Set by a proven frozen void (§4.16).
    pub destination_frozen: bool,
    /// Pause state of the latest control message (§4.14.6).
    pub destination_paused: bool,
    /// Next control nonce; starts at 1.
    pub next_control_nonce: u64,
    /// Supply cap in Taira units (equal to token units); equals the contract cap.
    #[norito(json = "crate::json_helpers::u128_string")]
    pub max_wrapped_supply: u128,
    /// XOR locked for this revision and not yet released or refunded.
    #[norito(json = "crate::json_helpers::u128_string")]
    pub liability: u128,
    /// Next outbound nonce; dense from 0.
    pub next_outbound_nonce: u64,
    /// Taira height of the enacted `RegisterRoute`.
    pub registered_at_height: u64,
    /// Whether the revision ever left `Staged`; `RemoveStaged` requires `false`.
    pub ever_activated: bool,
}

impl SccpRouteRevisionV1 {
    /// Build a freshly registered `Staged` revision from the exact P1–P5-checked pin.
    /// This data constructor does not authenticate a pin or bypass the registration launch gate.
    #[must_use]
    pub fn staged(
        revision: u32,
        deployment: SccpDeploymentV1,
        initial_committee: SccpCommitteePinV1,
        max_wrapped_supply: u128,
        registered_at_height: u64,
    ) -> Self {
        Self {
            revision,
            destination_word: deployment.destination_word(),
            deployment,
            initial_committee,
            activation: SccpRouteActivationV1::Staged,
            destination_frozen: false,
            destination_paused: false,
            next_control_nonce: SCCP_FIRST_CONTROL_NONCE_V1,
            max_wrapped_supply,
            liability: 0,
            next_outbound_nonce: 0,
            registered_at_height,
            ever_activated: false,
        }
    }

    /// Return the unused cap: `max_wrapped_supply − liability` (zero if over-committed).
    #[must_use]
    pub const fn headroom(&self) -> u128 {
        self.max_wrapped_supply.saturating_sub(self.liability)
    }
}

/// One route (`sccp_routes[network]`, §4.14.1).
#[derive(
    Debug,
    Clone,
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
#[norito_schema(name = "iroha_data_model::sccp::registry::SccpRouteV1")]
pub struct SccpRouteV1 {
    /// External network.
    pub network: SccpNetworkV1,
    /// Route id ([`route_id_for`]).
    pub route_id: String,
    /// Route escrow (`sccp_route_escrow_account_id_v1`, §4.15).
    pub escrow: AccountId,
    /// Value that can leave the escrow only through `ReleaseStranded` (§4.16).
    #[norito(json = "crate::json_helpers::u128_string")]
    pub stranded: u128,
    /// Revisions by number.
    pub revisions: BTreeMap<u32, SccpRouteRevisionV1>,
}

impl SccpRouteV1 {
    /// Build the empty route of an external `network` with its escrow, or `None` for
    /// `sora-taira`.
    #[must_use]
    pub fn empty(network: SccpNetworkV1, escrow: AccountId) -> Option<Self> {
        let route_id = route_id_for(network)?;
        Some(Self {
            network,
            route_id: route_id.to_owned(),
            escrow,
            stranded: 0,
            revisions: BTreeMap::new(),
        })
    }

    /// Return the highest registered revision number (0 when none).
    #[must_use]
    pub fn latest_revision(&self) -> u32 {
        self.revisions.keys().next_back().copied().unwrap_or(0)
    }

    /// Return the live (`Bidirectional` or `Paused`) revision, if any.
    #[must_use]
    pub fn live_revision(&self) -> Option<&SccpRouteRevisionV1> {
        self.revisions
            .values()
            .find(|revision| revision.activation.is_live())
    }

    /// Return the `Bidirectional` revision, if any.
    #[must_use]
    pub fn bidirectional_revision(&self) -> Option<&SccpRouteRevisionV1> {
        self.live_revision()
            .filter(|revision| revision.activation == SccpRouteActivationV1::Bidirectional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::{
        deployment::SccpEvmDeploymentV1,
        test_support::{assert_rejects_unknown_field, roundtrip},
    };
    use iroha_crypto::{Algorithm, KeyPair};

    const ALL: [SccpRouteActivationV1; 5] = [
        SccpRouteActivationV1::Staged,
        SccpRouteActivationV1::Bidirectional,
        SccpRouteActivationV1::Paused,
        SccpRouteActivationV1::InboundOnly,
        SccpRouteActivationV1::Retired,
    ];

    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic Ed25519 seed");
        AccountId::new(key_pair.public_key().clone())
    }

    fn evm(seed: u8) -> SccpDeploymentV1 {
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [seed; 20],
            runtime_code_hash: [0xc0; 32],
        })
    }

    fn revision(number: u32, activation: SccpRouteActivationV1) -> SccpRouteRevisionV1 {
        SccpRouteRevisionV1 {
            activation,
            liability: u128::from(number) * 100,
            ..SccpRouteRevisionV1::staged(
                number,
                evm(u8::try_from(number).expect("small")),
                crate::sccp::deployment::SccpCommitteePinV1 {
                    generation: 1,
                    committee_root: [0x44; 32],
                    start_height: 1,
                    until_ms: 1_801_209_600_000,
                },
                10_000,
                50,
            )
        }
    }

    #[test]
    fn route_ids_match_the_spec() {
        assert_eq!(route_id_for(SccpNetworkV1::SoraTaira), None);
        assert_eq!(
            route_id_for(SccpNetworkV1::EthereumMainnet),
            Some("taira_eth_xor")
        );
        assert_eq!(
            route_id_for(SccpNetworkV1::BscMainnet),
            Some("taira_bsc_xor")
        );
        assert_eq!(
            route_id_for(SccpNetworkV1::TonMainnet),
            Some("taira_ton_xor")
        );
        assert!(
            SCCP_ROUTE_NETWORKS_V1
                .iter()
                .all(|network| network.is_external() && route_id_for(*network).is_some())
        );
    }

    #[test]
    fn route_networks_are_ethereum_bsc_ton() {
        assert_eq!(
            SCCP_ROUTE_NETWORKS_V1,
            [
                SccpNetworkV1::EthereumMainnet,
                SccpNetworkV1::BscMainnet,
                SccpNetworkV1::TonMainnet,
            ]
        );
        assert_eq!(
            SCCP_ROUTE_NETWORKS_V1.map(|network| route_id_for(network).expect("route")),
            ["taira_eth_xor", "taira_bsc_xor", "taira_ton_xor"]
        );
    }

    #[test]
    fn activation_table_matches_the_spec() {
        // (state, settles, live)
        let table = [
            (SccpRouteActivationV1::Staged, false, false),
            (SccpRouteActivationV1::Bidirectional, true, true),
            (SccpRouteActivationV1::Paused, false, true),
            (SccpRouteActivationV1::InboundOnly, true, false),
            (SccpRouteActivationV1::Retired, false, false),
        ];
        for (state, settles, live) in table {
            assert_eq!(state.settles(), settles, "{state:?}");
            assert_eq!(state.is_live(), live, "{state:?}");
        }
    }

    #[test]
    fn transitions_match_the_spec() {
        use SccpRouteActivationV1::{Bidirectional, InboundOnly, Paused, Retired, Staged};
        let allowed = [
            (Staged, Bidirectional),
            (Bidirectional, Paused),
            (Paused, Bidirectional),
            (Bidirectional, InboundOnly),
            (Paused, InboundOnly),
            (InboundOnly, Retired),
        ];
        for from in ALL {
            for to in ALL {
                assert_eq!(
                    from.can_transition_to(to),
                    allowed.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn staged_revision_defaults() {
        let deployment = evm(9);
        let staged = SccpRouteRevisionV1::staged(
            2,
            deployment,
            crate::sccp::deployment::SccpCommitteePinV1 {
                generation: 1,
                committee_root: [0x44; 32],
                start_height: 1,
                until_ms: 1_801_209_600_000,
            },
            1_000,
            99,
        );
        assert_eq!(staged.revision, 2);
        assert_eq!(
            staged.initial_committee,
            SccpCommitteePinV1 {
                generation: 1,
                committee_root: [0x44; 32],
                start_height: 1,
                until_ms: 1_801_209_600_000
            }
        );
        assert_eq!(staged.destination_word, deployment.destination_word());
        assert_eq!(staged.activation, SccpRouteActivationV1::Staged);
        assert_eq!(staged.next_control_nonce, 1);
        assert_eq!(staged.next_outbound_nonce, 0);
        assert_eq!(staged.liability, 0);
        assert!(!staged.destination_frozen);
        assert!(!staged.destination_paused);
        assert!(!staged.ever_activated);
        assert_eq!(staged.registered_at_height, 99);
        assert_eq!(staged.headroom(), 1_000);
        let over = SccpRouteRevisionV1 {
            liability: 2_000,
            ..staged
        };
        assert_eq!(over.headroom(), 0);
    }

    #[test]
    fn route_queries() {
        assert_eq!(
            SccpRouteV1::empty(SccpNetworkV1::SoraTaira, account(1)),
            None
        );
        let mut route = SccpRouteV1::empty(SccpNetworkV1::EthereumMainnet, account(1))
            .expect("external network");
        assert_eq!(route.route_id, "taira_eth_xor");
        assert_eq!(route.latest_revision(), 0);
        assert!(route.live_revision().is_none());
        route
            .revisions
            .insert(1, revision(1, SccpRouteActivationV1::InboundOnly));
        route
            .revisions
            .insert(2, revision(2, SccpRouteActivationV1::Paused));
        route
            .revisions
            .insert(3, revision(3, SccpRouteActivationV1::Staged));
        assert_eq!(route.latest_revision(), 3);
        assert_eq!(route.live_revision().map(|r| r.revision), Some(2));
        assert!(route.bidirectional_revision().is_none());
        route.revisions.get_mut(&2).expect("revision 2").activation =
            SccpRouteActivationV1::Bidirectional;
        assert_eq!(route.bidirectional_revision().map(|r| r.revision), Some(2));
    }

    #[test]
    fn binary_and_json_roundtrip() {
        for state in ALL {
            roundtrip(&state);
            roundtrip(&revision(4, state));
        }
        let mut route =
            SccpRouteV1::empty(SccpNetworkV1::BscMainnet, account(2)).expect("external network");
        roundtrip(&route);
        route.stranded = u128::MAX;
        route
            .revisions
            .insert(1, revision(1, SccpRouteActivationV1::InboundOnly));
        route
            .revisions
            .insert(2, revision(2, SccpRouteActivationV1::Bidirectional));
        roundtrip(&route);
        assert_rejects_unknown_field(&route, &[]);
        assert_rejects_unknown_field(&route, &["revisions", "1"]);
        assert_rejects_unknown_field(&route, &["revisions", "1", "initial_committee"]);
        // The roster pin of the attestation transport is not a field of a revision.
        let mut value =
            norito::json::to_value(&revision(1, SccpRouteActivationV1::Staged)).expect("value");
        let object = value.as_object_mut().expect("object");
        assert!(object.contains_key("initial_committee"));
        let mut missing = object.clone();
        missing.remove("initial_committee");
        assert!(
            norito::json::from_value::<SccpRouteRevisionV1>(norito::json::Value::Object(missing))
                .is_err()
        );
        assert!(!object.contains_key("initial_roster_generation"));
        assert!(!object.contains_key("initial_roster_digest"));
        object.insert(
            "initial_roster_generation".to_owned(),
            norito::json::Value::from(3_u64),
        );
        let hostile = norito::json::to_json(&value).expect("json");
        assert!(norito::json::from_json::<SccpRouteRevisionV1>(&hostile).is_err());
        let json = norito::json::to_json(&route).expect("json");
        assert!(
            json.contains(&format!("\"stranded\":\"{}\"", u128::MAX)),
            "{json}"
        );
    }
}
