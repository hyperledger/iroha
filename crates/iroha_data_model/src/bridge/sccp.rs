//! SCCP network profile wire type.
//!
//! `SccpNetworkV1` models only the first-release network inventory (`specs/sccp.md` preamble and
//! §2). There is no catch-all network or arbitrary network identifier: unsupported profiles must
//! fail decoding instead of being interpreted by node-local policy. Every other SCCP v1 type lives
//! in [`crate::sccp`].

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
/// A supported SCCP network profile for the V1 wire format.
///
/// Tag `0x43` and SCCP domain 5 belonged to the removed TRON profile. Both stay unassigned and
/// fail decoding (`specs/sccp.md` preamble and §2.1).
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
#[norito(tag = "network", content = "profile")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::bridge::sccp::SccpNetworkV1")]
pub enum SccpNetworkV1 {
    /// The sole production SORA endpoint admitted by SCCP V1.
    #[codec(index = 64)]
    #[norito(rename = "sora_taira")]
    SoraTaira,
    /// Ethereum mainnet.
    #[codec(index = 65)]
    #[norito(rename = "ethereum_mainnet")]
    EthereumMainnet,
    /// BNB Smart Chain mainnet.
    #[codec(index = 66)]
    #[norito(rename = "bsc_mainnet")]
    BscMainnet,
    /// TON mainnet (global id −239).
    #[codec(index = 68)]
    #[norito(rename = "ton_mainnet")]
    TonMainnet,
}
impl SccpNetworkV1 {
    /// Return the SCCP protocol domain carried by messages for this profile.
    #[must_use]
    pub const fn domain_id(self) -> u32 {
        match self {
            Self::SoraTaira => 0,
            Self::EthereumMainnet => 1,
            Self::BscMainnet => 2,
            Self::TonMainnet => 4,
        }
    }
    /// Return the canonical, stable textual key for this exact profile.
    #[must_use]
    pub const fn profile_key(self) -> &'static str {
        match self {
            Self::SoraTaira => "sora-taira",
            Self::EthereumMainnet => "ethereum-mainnet",
            Self::BscMainnet => "bsc-mainnet",
            Self::TonMainnet => "ton-mainnet",
        }
    }
    /// Parse an exact canonical profile key.
    ///
    /// Parsing is deliberately case-sensitive and accepts neither domain-wide
    /// aliases nor abbreviated chain names. This makes textual storage keys a
    /// one-to-one representation of the closed V1 network inventory.
    #[must_use]
    pub fn from_profile_key(profile: &str) -> Option<Self> {
        match profile {
            "sora-taira" => Some(Self::SoraTaira),
            "ethereum-mainnet" => Some(Self::EthereumMainnet),
            "bsc-mainnet" => Some(Self::BscMainnet),
            "ton-mainnet" => Some(Self::TonMainnet),
            _ => None,
        }
    }
    /// Return whether this profile belongs to the SORA domain.
    #[must_use]
    pub const fn is_sora(self) -> bool {
        matches!(self, Self::SoraTaira)
    }
    /// Return whether this profile is a supported external SCCP endpoint.
    #[must_use]
    pub const fn is_external(self) -> bool {
        !self.is_sora()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::DecodeAll as _;
    const NETWORKS: [SccpNetworkV1; 4] = [
        SccpNetworkV1::SoraTaira,
        SccpNetworkV1::EthereumMainnet,
        SccpNetworkV1::BscMainnet,
        SccpNetworkV1::TonMainnet,
    ];
    #[test]
    fn network_inventory_and_profile_keys_are_exact() {
        assert_eq!(NETWORKS.len(), 4);
        for network in NETWORKS {
            assert_eq!(
                SccpNetworkV1::from_profile_key(network.profile_key()),
                Some(network)
            );
        }
        for unsupported in [
            "",
            "sora-nexus",
            "sora_nexus",
            "ethereum",
            "ethereum-sepolia",
            "ETHEREUM-MAINNET",
            "bsc-testnet",
            "tron-mainnet",
            "tron_mainnet",
            "tron-nile",
            "tron-shasta",
            "solana-mainnet-beta",
            "solana-testnet",
            "solana_testnet",
            "ton",
            "ton-testnet",
            "TON-MAINNET",
            "ton_mainnet",
        ] {
            assert_eq!(SccpNetworkV1::from_profile_key(unsupported), None);
        }
        assert_eq!(SccpNetworkV1::SoraTaira.domain_id(), 0);
        assert_eq!(SccpNetworkV1::EthereumMainnet.domain_id(), 1);
        assert_eq!(SccpNetworkV1::BscMainnet.domain_id(), 2);
        assert_eq!(SccpNetworkV1::TonMainnet.domain_id(), 4);
    }
    #[test]
    fn retired_tron_tag_0x43_and_profile_keys_do_not_decode() {
        let retired_tag = 0x43_u32.encode();
        assert!(SccpNetworkV1::decode_all(&mut retired_tag.as_slice()).is_err());
        for profile in ["tron-mainnet", "tron_mainnet"] {
            assert_eq!(SccpNetworkV1::from_profile_key(profile), None);
        }
        let json = r#"{"network":"tron_mainnet","profile":null}"#;
        assert!(norito::json::from_json::<SccpNetworkV1>(json).is_err());
        assert!(NETWORKS.iter().all(|network| network.domain_id() != 5));
    }
    #[test]
    fn network_binary_roundtrips_cover_the_closed_inventory() {
        for network in NETWORKS {
            let encoded = network.encode();
            assert_eq!(
                SccpNetworkV1::decode_all(&mut encoded.as_slice()).expect("network decodes"),
                network
            );
        }
    }
    #[test]
    fn unknown_binary_network_tags_are_rejected() {
        for unsupported_tag in [
            0_u32,
            1,
            2,
            3,
            4,
            5,
            10,
            11,
            12,
            13,
            14,
            15,
            63,
            0x43,
            69,
            u32::MAX,
        ] {
            let encoded = unsupported_tag.encode();
            assert!(
                SccpNetworkV1::decode_all(&mut encoded.as_slice()).is_err(),
                "network tag {unsupported_tag} unexpectedly decoded"
            );
        }
    }
    #[test]
    fn binary_tags_use_the_fresh_final_v1_block() {
        let expected = [
            (SccpNetworkV1::SoraTaira, 0x40_u32),
            (SccpNetworkV1::EthereumMainnet, 0x41),
            (SccpNetworkV1::BscMainnet, 0x42),
            (SccpNetworkV1::TonMainnet, 0x44),
        ];
        for (network, tag) in expected {
            assert_eq!(
                network.encode().get(..4),
                Some(tag.to_le_bytes().as_slice()),
                "wrong Norito tag for {network:?}"
            );
        }
    }
    #[test]
    fn unsupported_networks_are_not_json_decodable() {
        for profile in [
            "sora_nexus",
            "ethereum_sepolia",
            "bsc_testnet",
            "tron_mainnet",
            "tron_nile",
            "tron_shasta",
            "solana_testnet",
            "ton_testnet",
            "unknown_network",
        ] {
            let json = format!(r#"{{"network":"{profile}","profile":null}}"#);
            assert!(
                norito::json::from_json::<SccpNetworkV1>(&json).is_err(),
                "unsupported profile {profile} unexpectedly decoded"
            );
        }
    }
    #[test]
    fn json_roundtrips_advertise_only_first_release_profiles() {
        for network in NETWORKS {
            let json = norito::json::to_json(&network).expect("network serializes");
            assert_eq!(
                norito::json::from_json::<SccpNetworkV1>(&json).expect("network decodes"),
                network
            );
        }
    }
    #[test]
    fn sora_and_external_partition_the_inventory() {
        for network in NETWORKS {
            assert_eq!(network.is_external(), !network.is_sora());
            assert_eq!(network.is_sora(), network == SccpNetworkV1::SoraTaira);
        }
    }
}
#[cfg(test)]
mod captured_sccp_schema_tests;
