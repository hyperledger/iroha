//! Canonical command grammar and fail-closed profile/range review.

use super::*;
use clap::Parser as _;

fn profile_rows() -> (Vec<SccpLcProfileStatusV1>, [u8; 32]) {
    let active = SccpLcProfileCatalogV1::compiled().genesis();
    (
        SCCP_LC_PROFILE_NETWORKS_V1
            .into_iter()
            .map(|network| {
                let selected = active.get(network).unwrap();
                SccpLcProfileStatusV1 {
                    network,
                    version: selected.version,
                    profile_hash: selected.profile_hash,
                    activation_height: None,
                    proposal_id: None,
                    supported_until_ms: None,
                }
            })
            .collect(),
        active.policy_hash(),
    )
}

#[test]
fn committed_profile_resolution_rejects_missing_duplicate_unknown_and_mismatched_selection() {
    let (rows, policy) = profile_rows();
    assert_eq!(
        resolve_profiles(&rows, policy).unwrap(),
        iroha_sccp::light_client::profile::GENESIS_PROFILES
    );
    assert!(resolve_profiles(&rows[..2], policy).is_err());
    let mut changed = rows.clone();
    changed[1] = changed[0];
    assert!(resolve_profiles(&changed, policy).is_err());
    let mut changed = rows.clone();
    changed[0].profile_hash[0] ^= 1;
    assert!(resolve_profiles(&changed, policy).is_err());
    let mut active = SccpLcProfileCatalogV1::compiled().genesis();
    changed[0].version = u32::MAX;
    active = active.with(
        changed[0].network,
        SccpLcProfileRefV1 {
            version: changed[0].version,
            profile_hash: changed[0].profile_hash,
        },
    );
    assert!(
        resolve_profiles(&changed, active.policy_hash())
            .unwrap_err()
            .to_string()
            .contains("does not compile")
    );
    assert!(resolve_profiles(&rows, [0; 32]).is_err());
}

#[test]
fn backfill_range_is_inclusive_and_capped_before_rpc_allocation() {
    assert_eq!(backfill_range(7, 10, 4).unwrap(), vec![7, 8, 9, 10]);
    assert_eq!(
        backfill_range(u64::MAX - 1, u64::MAX, 2).unwrap(),
        vec![u64::MAX - 1, u64::MAX]
    );
    for (first, last, bound) in [
        (7, 10, 3),
        (10, 10, 4),
        (11, 10, 4),
        (0, u64::MAX, u32::MAX),
        (0, 1, 0),
    ] {
        assert!(backfill_range(first, last, bound).is_err());
    }
}

#[test]
fn bootstrap_review_rejects_other_actions_and_malformed_chain_evidence() {
    use iroha::data_model::sccp::{
        governance::{SccpActivateLightClientProfileActionV1, SccpInitializeLightClientActionV1},
        light_client::{SccpLcBootstrapV1, SccpLcInitExpectationV1, SccpLightClientParamsV1},
    };
    let network = SccpNetworkV1::EthereumMainnet;
    let profiles = iroha_sccp::light_client::profile::GENESIS_PROFILES;
    let wrong = SccpGovernanceActionV1::ActivateLightClientProfile(
        SccpActivateLightClientProfileActionV1 {
            network,
            version: 2,
            profile_hash: [0; 32],
        },
    );
    assert!(
        verify_actions(&profiles, &[wrong], 0)
            .unwrap_err()
            .to_string()
            .contains("only InitializeLightClient")
    );
    let malformed =
        SccpGovernanceActionV1::InitializeLightClient(SccpInitializeLightClientActionV1 {
            network,
            expected: SccpLcInitExpectationV1::Absent,
            params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
            bootstrap: SccpLcBootstrapV1 {
                network,
                bytes: vec![0],
            },
        });
    assert!(
        verify_actions(&profiles, &[malformed], 0)
            .unwrap_err()
            .to_string()
            .contains("bootstrap rejected")
    );
}

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: super::super::Command,
}

#[test]
fn canonical_light_client_commands_require_exact_backfill_and_review_inputs() {
    for args in [
        vec!["iroha", "light-client", "status"],
        vec![
            "iroha",
            "light-client",
            "bootstrap",
            "verify",
            "--actions",
            "actions.json",
        ],
        vec![
            "iroha",
            "light-client",
            "backfill",
            "--network",
            "ethereum-mainnet",
            "--rpc-url",
            "https://rpc.invalid",
            "--first-height",
            "1",
            "--checkpoint-height",
            "2",
        ],
        vec![
            "iroha",
            "light-client",
            "bootstrap",
            "build",
            "--network",
            "ton-mainnet",
            "--rpc-url",
            "https://rpc.invalid",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    for args in [
        vec!["iroha", "lc-advance"],
        vec!["iroha", "lc-bootstrap"],
        vec!["iroha", "light-client", "bootstrap", "verify"],
        vec![
            "iroha",
            "light-client",
            "backfill",
            "--network",
            "bsc-mainnet",
            "--rpc-url",
            "https://rpc.invalid",
            "--first-height",
            "1",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}
