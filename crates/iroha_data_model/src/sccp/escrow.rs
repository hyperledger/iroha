//! SCCP v1 route escrow identity (`specs/sccp.md` §4.15).
//!
//! One escrow account per route holds every XOR the route has locked. Its id is derived from
//! the live Taira `NetworkId`, the route id and the asset id — never from a revision — as a
//! hash-to-point Ed25519 public key with no known scalar, so nobody can sign for it.
//! `InitializeSccpV1` creates all three escrows in genesis.

use super::registry::route_id_for;
use crate::{NetworkId, account::AccountId, asset::AssetDefinitionId, bridge::SccpNetworkV1};
use iroha_crypto::derive_non_signing_ed25519_public_key;

/// Domain tag of the route escrow derivation.
pub const SCCP_ROUTE_ESCROW_DOMAIN_V1: &[u8] = b"iroha:sccp:v1:route-escrow";
/// SCCP `asset_id` text of Taira XOR (§3.2).
pub const SCCP_XOR_ASSET_ID_TEXT: &str = "xor";
/// Canonical address literal of the Taira XOR asset definition.
pub const SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

/// Derive the non-signable escrow account of one route (§4.15).
///
/// The derivation is revision-free: every revision of a route shares the escrow. Each input is
/// length-framed by [`derive_non_signing_ed25519_public_key`], so distinct `(network_id,
/// route_id, asset_id)` triples never collide by concatenation.
#[must_use]
pub fn sccp_route_escrow_account_id_v1(
    network_id: &NetworkId,
    route_id: &str,
    asset_id: &str,
) -> AccountId {
    AccountId::new(derive_non_signing_ed25519_public_key(
        SCCP_ROUTE_ESCROW_DOMAIN_V1,
        &[
            network_id.as_bytes(),
            route_id.as_bytes(),
            asset_id.as_bytes(),
        ],
    ))
}

/// Return the XOR escrow of `network`'s route, or `None` for `sora-taira`.
#[must_use]
pub fn sccp_xor_route_escrow_account_id_v1(
    network_id: &NetworkId,
    network: SccpNetworkV1,
) -> Option<AccountId> {
    route_id_for(network).map(|route_id| {
        sccp_route_escrow_account_id_v1(network_id, route_id, SCCP_XOR_ASSET_ID_TEXT)
    })
}

/// Return the canonical Taira XOR asset definition id.
///
/// The literal is release protocol state covered by tests, so a parse failure is a programmer
/// error.
#[must_use]
pub fn sccp_taira_xor_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1)
        .expect("built-in SCCP Taira XOR asset definition id must remain valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::registry::{
        SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1,
        SCCP_ROUTE_ID_TAIRA_TON_XOR_V1,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf};
    use std::collections::BTreeSet;

    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
            Hash::new([seed; Hash::LENGTH]),
        ))
    }

    const ROUTES: [&str; 3] = [
        SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1,
        SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1,
        SCCP_ROUTE_ID_TAIRA_TON_XOR_V1,
    ];

    #[test]
    fn constants_match_the_spec() {
        assert_eq!(SCCP_ROUTE_ESCROW_DOMAIN_V1, b"iroha:sccp:v1:route-escrow");
        assert_eq!(SCCP_XOR_ASSET_ID_TEXT, "xor");
    }

    #[test]
    fn escrow_ids_are_deterministic_and_distinct() {
        let mut seen = BTreeSet::new();
        for seed in [1_u8, 2] {
            let id = network_id(seed);
            for route in ROUTES {
                let escrow = sccp_route_escrow_account_id_v1(&id, route, SCCP_XOR_ASSET_ID_TEXT);
                assert_eq!(
                    escrow,
                    sccp_route_escrow_account_id_v1(&id, route, SCCP_XOR_ASSET_ID_TEXT),
                    "deterministic"
                );
                assert!(seen.insert(escrow), "distinct per route and NetworkId");
            }
        }
        assert_eq!(seen.len(), 6);
        let id = network_id(1);
        assert_ne!(
            sccp_route_escrow_account_id_v1(&id, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1, "xor"),
            sccp_route_escrow_account_id_v1(&id, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1, "val"),
            "distinct per asset"
        );
        assert_ne!(
            sccp_route_escrow_account_id_v1(&id, "ab", "c"),
            sccp_route_escrow_account_id_v1(&id, "a", "bc"),
            "inputs are length-framed"
        );
    }

    #[test]
    fn escrow_key_is_ed25519_and_network_helper_matches() {
        let id = network_id(3);
        let escrow = sccp_route_escrow_account_id_v1(&id, SCCP_ROUTE_ID_TAIRA_TON_XOR_V1, "xor");
        let controller = escrow
            .try_signatory()
            .expect("escrow is a single-key account");
        assert_eq!(controller.algorithm(), Algorithm::Ed25519);
        assert_eq!(
            sccp_xor_route_escrow_account_id_v1(&id, SccpNetworkV1::TonMainnet),
            Some(escrow)
        );
        assert_eq!(
            sccp_xor_route_escrow_account_id_v1(&id, SccpNetworkV1::SoraTaira),
            None
        );
        for (network, route) in [
            (
                SccpNetworkV1::EthereumMainnet,
                SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1,
            ),
            (SccpNetworkV1::BscMainnet, SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1),
        ] {
            assert_eq!(
                sccp_xor_route_escrow_account_id_v1(&id, network),
                Some(sccp_route_escrow_account_id_v1(&id, route, "xor"))
            );
        }
    }

    #[test]
    fn taira_xor_definition_literal_parses_and_roundtrips() {
        let definition = sccp_taira_xor_asset_definition_id();
        assert_eq!(
            definition,
            AssetDefinitionId::parse_address_literal(SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1)
                .expect("valid literal")
        );
        assert_eq!(
            definition.to_string(),
            SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1
        );
    }
}
