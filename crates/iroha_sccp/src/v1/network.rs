//! SCCP v1 profiles, identity words and lanes (spec §2).
//!
//! The four first-release profiles, their 1-byte tags, 32-byte identity words,
//! `network_bytes(p) = tag(p) ‖ identity_word(p)` (33 bytes) and
//! `lane_bytes(source, target) = network_bytes(source) ‖ network_bytes(target)` (66 bytes).
//! Taira's identity word is its runtime `NetworkId` (the genesis header hash); nothing
//! Taira-specific is compiled in, so every function takes the Taira network id as input.

use iroha_data_model::bridge::SccpNetworkV1;

use super::{
    constants::{
        BSC_CHAIN_ID, CODEC_EVM_ADDRESS20, CODEC_TAIRA_ACCOUNT, CODEC_TON_ACCOUNT36, DOMAIN_BSC,
        DOMAIN_ETHEREUM, DOMAIN_SORA_TAIRA, DOMAIN_TON, ETHEREUM_CHAIN_ID,
        MAX_VOID_FROZEN_RANGE_EVM, MAX_VOID_FROZEN_RANGE_TON, ROUTE_ID_BSC, ROUTE_ID_ETHEREUM,
        ROUTE_ID_TON, TAG_BSC, TAG_ETHEREUM, TAG_SORA_TAIRA, TAG_TON, TON_GLOBAL_ID,
    },
    hashes::word_u64,
};

/// Every first-release profile in tag order.
pub const ALL_NETWORKS: [SccpNetworkV1; 4] = [
    SccpNetworkV1::SoraTaira,
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

/// The three external profiles in tag order.
pub const EXTERNAL_NETWORKS: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

/// Profile tag (§2.1): `0x40`, `0x41`, `0x42` or `0x44`. Tag `0x43` is unassigned.
#[must_use]
pub const fn tag(network: SccpNetworkV1) -> u8 {
    match network {
        SccpNetworkV1::SoraTaira => TAG_SORA_TAIRA,
        SccpNetworkV1::EthereumMainnet => TAG_ETHEREUM,
        SccpNetworkV1::BscMainnet => TAG_BSC,
        SccpNetworkV1::TonMainnet => TAG_TON,
    }
}

/// SCCP domain id of a profile (Taira 0, ETH 1, BSC 2, TON 4). Domain 5 is unassigned.
#[must_use]
pub const fn domain(network: SccpNetworkV1) -> u32 {
    match network {
        SccpNetworkV1::SoraTaira => DOMAIN_SORA_TAIRA,
        SccpNetworkV1::EthereumMainnet => DOMAIN_ETHEREUM,
        SccpNetworkV1::BscMainnet => DOMAIN_BSC,
        SccpNetworkV1::TonMainnet => DOMAIN_TON,
    }
}

/// Profile of an SCCP domain id, if any. Domain 5 belonged to the removed TRON profile and has
/// none.
#[must_use]
pub const fn network_from_domain(domain: u32) -> Option<SccpNetworkV1> {
    match domain {
        DOMAIN_SORA_TAIRA => Some(SccpNetworkV1::SoraTaira),
        DOMAIN_ETHEREUM => Some(SccpNetworkV1::EthereumMainnet),
        DOMAIN_BSC => Some(SccpNetworkV1::BscMainnet),
        DOMAIN_TON => Some(SccpNetworkV1::TonMainnet),
        _ => None,
    }
}

/// Route id text of an external profile (§2.3); `None` for Taira.
#[must_use]
pub const fn route_id(network: SccpNetworkV1) -> Option<&'static str> {
    match network {
        SccpNetworkV1::SoraTaira => None,
        SccpNetworkV1::EthereumMainnet => Some(ROUTE_ID_ETHEREUM),
        SccpNetworkV1::BscMainnet => Some(ROUTE_ID_BSC),
        SccpNetworkV1::TonMainnet => Some(ROUTE_ID_TON),
    }
}

/// Account codec of an external profile's own accounts (§3.1, §3.2); `None` for Taira.
///
/// This is the recipient codec of Taira → X and the sender codec of X → Taira.
#[must_use]
pub const fn external_account_codec(network: SccpNetworkV1) -> Option<u8> {
    match network {
        SccpNetworkV1::SoraTaira => None,
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => Some(CODEC_EVM_ADDRESS20),
        SccpNetworkV1::TonMainnet => Some(CODEC_TON_ACCOUNT36),
    }
}

/// Account codec of a profile's own accounts, Taira included (codec 3).
#[must_use]
pub const fn account_codec(network: SccpNetworkV1) -> u8 {
    match external_account_codec(network) {
        Some(codec) => codec,
        None => CODEC_TAIRA_ACCOUNT,
    }
}

/// EVM `block.chainid` of an EVM profile (ETH, BSC); `None` otherwise.
#[must_use]
pub const fn evm_chain_id(network: SccpNetworkV1) -> Option<u64> {
    match network {
        SccpNetworkV1::EthereumMainnet => Some(ETHEREUM_CHAIN_ID),
        SccpNetworkV1::BscMainnet => Some(BSC_CHAIN_ID),
        SccpNetworkV1::SoraTaira | SccpNetworkV1::TonMainnet => None,
    }
}

/// Most nonces one frozen void of an external destination may name (§4.16, §5.1.8): the
/// `voidFrozen` range bound on ETH and BSC, one `sccp_void_frozen` bucket on TON; `None` for
/// Taira, which is never a destination.
#[must_use]
pub const fn max_void_frozen_range(network: SccpNetworkV1) -> Option<u64> {
    match network {
        SccpNetworkV1::SoraTaira => None,
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => {
            Some(MAX_VOID_FROZEN_RANGE_EVM)
        }
        SccpNetworkV1::TonMainnet => Some(MAX_VOID_FROZEN_RANGE_TON),
    }
}

/// Two's-complement `int256` word of a signed 32-bit value.
#[must_use]
pub fn word_i32(value: i32) -> [u8; 32] {
    let fill = if value < 0 { 0xff } else { 0x00 };
    let mut word = [fill; 32];
    word[28..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Identity word of a profile (§2.1).
///
/// Taira: the 32 bytes of its `NetworkId`; ETH `word(1)`; BSC `word(56)`; TON
/// two's-complement `int256(-239)`.
#[must_use]
pub fn identity_word(network: SccpNetworkV1, taira_network_id: &[u8; 32]) -> [u8; 32] {
    match network {
        SccpNetworkV1::SoraTaira => *taira_network_id,
        SccpNetworkV1::EthereumMainnet => word_u64(ETHEREUM_CHAIN_ID),
        SccpNetworkV1::BscMainnet => word_u64(BSC_CHAIN_ID),
        SccpNetworkV1::TonMainnet => word_i32(TON_GLOBAL_ID),
    }
}

/// `network_bytes(p) = tag(p) ‖ identity_word(p)` (33 bytes).
#[must_use]
pub fn network_bytes(network: SccpNetworkV1, taira_network_id: &[u8; 32]) -> [u8; 33] {
    let mut out = [0_u8; 33];
    out[0] = tag(network);
    out[1..].copy_from_slice(&identity_word(network, taira_network_id));
    out
}

/// `lane_bytes(source, target)` (66 bytes); `None` unless exactly one endpoint is Taira.
#[must_use]
pub fn lane_bytes(
    source: SccpNetworkV1,
    target: SccpNetworkV1,
    taira_network_id: &[u8; 32],
) -> Option<[u8; 66]> {
    if source.is_sora() == target.is_sora() {
        return None;
    }
    let mut out = [0_u8; 66];
    out[..33].copy_from_slice(&network_bytes(source, taira_network_id));
    out[33..].copy_from_slice(&network_bytes(target, taira_network_id));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAIRA: [u8; 32] = [0x11; 32];

    #[test]
    fn domains_roundtrip_and_taira_has_no_route() {
        for network in ALL_NETWORKS {
            assert_eq!(network_from_domain(domain(network)), Some(network));
            assert_eq!(domain(network), network.domain_id());
        }
        // Domain 5 belonged to the removed TRON profile.
        for unassigned in [3, 5, 6, u32::MAX] {
            assert_eq!(network_from_domain(unassigned), None, "{unassigned}");
        }
        assert_eq!(route_id(SccpNetworkV1::SoraTaira), None);
        assert_eq!(
            EXTERNAL_NETWORKS.map(|network| route_id(network).expect("external route")),
            ["taira_eth_xor", "taira_bsc_xor", "taira_ton_xor"]
        );
    }

    #[test]
    fn tags_are_the_spec_table_and_0x43_is_unassigned() {
        assert_eq!(ALL_NETWORKS.map(tag), [0x40, 0x41, 0x42, 0x44]);
        assert_eq!(ALL_NETWORKS.map(domain), [0, 1, 2, 4]);
        assert_eq!(ALL_NETWORKS[1..], EXTERNAL_NETWORKS);
    }

    #[test]
    fn identity_words_match_the_spec_table() {
        assert_eq!(identity_word(SccpNetworkV1::SoraTaira, &TAIRA), TAIRA);
        assert_eq!(
            identity_word(SccpNetworkV1::EthereumMainnet, &TAIRA),
            word_u64(1)
        );
        assert_eq!(
            identity_word(SccpNetworkV1::BscMainnet, &TAIRA),
            word_u64(56)
        );
        let ton_word = identity_word(SccpNetworkV1::TonMainnet, &TAIRA);
        assert_eq!(ton_word[..31], [0xff; 31]);
        assert_eq!(ton_word[31], 0x11);
    }

    #[test]
    fn word_i32_is_twos_complement() {
        assert_eq!(word_i32(0), [0; 32]);
        assert_eq!(word_i32(-1), [0xff; 32]);
        let mut expected = [0_u8; 32];
        expected[31] = 5;
        assert_eq!(word_i32(5), expected);
    }

    #[test]
    fn network_and_lane_bytes_layout() {
        let bytes = network_bytes(SccpNetworkV1::BscMainnet, &TAIRA);
        assert_eq!(bytes[0], 0x42);
        assert_eq!(bytes[32], 56);
        let lane = lane_bytes(SccpNetworkV1::SoraTaira, SccpNetworkV1::TonMainnet, &TAIRA)
            .expect("taira to ton");
        assert_eq!(lane[0], 0x40);
        assert_eq!(lane[1..33], TAIRA);
        assert_eq!(lane[33], 0x44);
        assert_eq!(lane[65], 0x11);
        let inbound = lane_bytes(SccpNetworkV1::BscMainnet, SccpNetworkV1::SoraTaira, &TAIRA)
            .expect("bsc to taira");
        assert_eq!(inbound[0], 0x42);
        assert_eq!(inbound[33], 0x40);
        assert!(lane_bytes(SccpNetworkV1::SoraTaira, SccpNetworkV1::SoraTaira, &TAIRA).is_none());
        assert!(
            lane_bytes(
                SccpNetworkV1::EthereumMainnet,
                SccpNetworkV1::BscMainnet,
                &TAIRA
            )
            .is_none()
        );
    }

    #[test]
    fn codecs_and_chain_ids() {
        assert_eq!(account_codec(SccpNetworkV1::SoraTaira), 3);
        assert_eq!(account_codec(SccpNetworkV1::EthereumMainnet), 2);
        assert_eq!(account_codec(SccpNetworkV1::BscMainnet), 2);
        assert_eq!(account_codec(SccpNetworkV1::TonMainnet), 7);
        assert_eq!(external_account_codec(SccpNetworkV1::SoraTaira), None);
        assert_eq!(evm_chain_id(SccpNetworkV1::EthereumMainnet), Some(1));
        assert_eq!(evm_chain_id(SccpNetworkV1::BscMainnet), Some(56));
        assert_eq!(evm_chain_id(SccpNetworkV1::TonMainnet), None);
    }

    #[test]
    fn frozen_void_ranges_follow_each_destination() {
        assert_eq!(max_void_frozen_range(SccpNetworkV1::SoraTaira), None);
        for network in [SccpNetworkV1::EthereumMainnet, SccpNetworkV1::BscMainnet] {
            assert_eq!(max_void_frozen_range(network), Some(256));
        }
        assert_eq!(max_void_frozen_range(SccpNetworkV1::TonMainnet), Some(512));
    }
}
