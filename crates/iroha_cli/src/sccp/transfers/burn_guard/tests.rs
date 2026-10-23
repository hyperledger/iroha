//! Pre-burn route, exact horizon, controller and original-set regression checks.

use super::*;
use iroha::data_model::account::curve::CurveId;
use iroha::data_model::sccp::{
    deployment::{SccpCommitteePinV1, SccpDeploymentV1, SccpEvmDeploymentV1},
    light_client::{SccpLcHeadV1, SccpLcPointV1, SccpLightClientParamsV1},
};

fn light_client(network: SccpNetworkV1) -> SccpLightClientV1 {
    SccpLightClientV1 {
        params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
        head: SccpLcHeadV1 {
            latest_set_id: 1,
            latest_finalized: SccpLcPointV1 {
                source_height: 2,
                block_hash: [3; 32],
                source_time_ms: 1000,
            },
            last_progress_taira_ms: 1000,
        },
        frozen: None,
        state_hash: [4; 32],
    }
}

#[test]
fn burn_route_accepts_inbound_drain_but_never_hold_or_quarantine() {
    let mut revision = SccpRouteRevisionV1::staged(
        1,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [1; 20],
            runtime_code_hash: [2; 32],
        }),
        SccpCommitteePinV1 {
            generation: 1,
            committee_root: [3; 32],
            start_height: 1,
            until_ms: 1000,
        },
        100,
        1,
    );
    assert!(require_route(&revision, None).is_err());
    revision.activation = SccpRouteActivationV1::Bidirectional;
    assert!(require_route(&revision, None).is_ok());
    revision.activation = SccpRouteActivationV1::InboundOnly;
    assert!(require_route(&revision, None).is_ok());
    assert!(require_route(&revision, Some(revision.forgery_floor)).is_err());
    revision.quarantine = Some(iroha::data_model::sccp::native::SccpQuarantineV1 {
        certificate_id: [7; 32],
        since_height: 1,
    });
    assert!(require_route(&revision, None).is_err());
    revision.quarantine = None;
    revision.activation = SccpRouteActivationV1::Paused;
    assert!(require_route(&revision, None).is_err());
}

#[test]
fn burn_horizons_round_the_quarter_up_and_refuse_the_exact_profile_margin() {
    let client = light_client(SccpNetworkV1::BscMainnet);
    let supported = Some(100 + PROFILE_MARGIN_MS + 1);
    assert!(require_horizon(&client, 100, 103, 9, supported).is_ok());
    assert!(require_horizon(&client, 100, 102, 9, supported).is_err());
    assert!(require_horizon(&client, 104, 103, 9, supported).is_err());
    assert!(require_horizon(&client, 100, 103, 9, Some(100 + PROFILE_MARGIN_MS)).is_err());
    assert!(require_horizon(&client, 100, 103, 9, None).is_err());
    assert!(require_horizon(&client, 100, 103, 0, supported).is_err());
    assert!(require_horizon(&client, u64::MAX, u64::MAX, 9, Some(u64::MAX)).is_err());
    let mut frozen = client;
    frozen.frozen = Some(
        iroha::data_model::sccp::light_client::SccpLcFreezeReasonV1::Parliament(
            iroha::data_model::sccp::light_client::SccpLcParliamentFreezeV1 {
                proposal_id: [1; 32],
            },
        ),
    );
    assert!(require_horizon(&frozen, 100, 103, 9, supported).is_err());
}

#[test]
fn burn_controller_requires_every_admitted_algorithm_and_curve() {
    let key = iroha_crypto::KeyPair::from_seed(vec![19; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let bytes = AccountAddress::from_account_id(&account)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let curve = CurveId::from_algorithm(Algorithm::Ed25519).as_u8();
    let good = norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519"]}, "curves": {"allowed_curve_ids": [curve]}}});
    assert_eq!(require_controller(&bytes, &good).unwrap(), account);
    for bad in [
        norito::json!({}),
        norito::json!({"crypto": {"sm": {"allowed_signing": []}, "curves": {"allowed_curve_ids": [curve]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519"]}, "curves": {"allowed_curve_ids": []}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["unknown"]}, "curves": {"allowed_curve_ids": [curve]}}}),
    ] {
        assert!(require_controller(&bytes, &bad).is_err());
    }
    assert!(require_controller(&[0; 1025], &good).is_err());
    let mut malformed = bytes.clone();
    malformed.push(0);
    assert!(require_controller(&malformed, &good).is_err());
}

#[test]
fn burn_multisig_checks_every_member_even_below_the_signing_threshold() {
    use iroha::data_model::account::controller::{MultisigMember, MultisigPolicy};

    let ed = iroha_crypto::KeyPair::from_seed(vec![21; 32], Algorithm::Ed25519);
    let secp = iroha_crypto::KeyPair::from_seed(vec![22; 32], Algorithm::Secp256k1);
    let account = AccountId::new_multisig(
        MultisigPolicy::new(
            1,
            vec![
                MultisigMember::new(ed.public_key().clone(), 1).unwrap(),
                MultisigMember::new(secp.public_key().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    let bytes = AccountAddress::from_account_id(&account)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let ed_curve = CurveId::from_algorithm(Algorithm::Ed25519).as_u8();
    let secp_curve = CurveId::from_algorithm(Algorithm::Secp256k1).as_u8();
    let permitted = norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519", "secp256k1"]}, "curves": {"allowed_curve_ids": [ed_curve, secp_curve]}}});
    assert_eq!(require_controller(&bytes, &permitted).unwrap(), account);
    for denied in [
        norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519"]}, "curves": {"allowed_curve_ids": [ed_curve, secp_curve]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519", "secp256k1"]}, "curves": {"allowed_curve_ids": [ed_curve]}}}),
    ] {
        assert!(
            require_controller(&bytes, &denied).is_err(),
            "one permitted signer cannot hide an inadmissible controller member"
        );
    }
}

#[test]
fn burn_bls_requires_committed_membership_without_exempting_other_members() {
    use iroha::data_model::account::controller::{MultisigMember, MultisigPolicy};

    let capabilities = |algorithms: Vec<Algorithm>| {
        let policy = CryptoAdmissionPolicyV1::new(algorithms).unwrap();
        norito::json!({"crypto": {"sm": {"allowed_signing": policy.allowed_algorithms().iter().map(|algorithm| algorithm.as_static_str()).collect::<Vec<_>>()}, "curves": {"allowed_curve_ids": policy.allowed_curves().map(|curve| curve.as_u8()).collect::<Vec<_>>()}}})
    };
    let ed_permitted = capabilities(vec![Algorithm::Ed25519]);
    let ed = iroha_crypto::KeyPair::from_seed(vec![24; 32], Algorithm::Ed25519);
    for algorithm in [Algorithm::BlsNormal, Algorithm::BlsSmall] {
        let bls = iroha_crypto::KeyPair::from_seed(vec![23; 32], algorithm);
        let single = AccountId::new(bls.public_key().clone());
        let bytes = AccountAddress::from_account_id(&single)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        assert!(require_controller(&bytes, &ed_permitted).is_err());
        let bls_permitted = capabilities(vec![algorithm]);
        assert_eq!(require_controller(&bytes, &bls_permitted).unwrap(), single);
        let mixed = AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                vec![
                    MultisigMember::new(bls.public_key().clone(), 1).unwrap(),
                    MultisigMember::new(ed.public_key().clone(), 1).unwrap(),
                ],
            )
            .unwrap(),
        );
        let bytes = AccountAddress::from_account_id(&mixed)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        assert!(require_controller(&bytes, &bls_permitted).is_err());
        assert!(require_controller(&bytes, &ed_permitted).is_err());
        let both_permitted = capabilities(vec![Algorithm::Ed25519, algorithm]);
        assert_eq!(require_controller(&bytes, &both_permitted).unwrap(), mixed);
    }
}

#[test]
fn burn_controller_rejects_noncanonical_policy_and_inconsistent_curve_projection() {
    let key = iroha_crypto::KeyPair::from_seed(vec![25; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let bytes = AccountAddress::from_account_id(&account)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let ed = CurveId::from_algorithm(Algorithm::Ed25519).as_u8();
    let secp = CurveId::from_algorithm(Algorithm::Secp256k1).as_u8();
    for invalid in [
        norito::json!({"crypto": {"sm": {"allowed_signing": vec!["ed25519"; Algorithm::ALL.len() + 1]}, "curves": {"allowed_curve_ids": vec![ed; Algorithm::ALL.len() + 1]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519", "ed25519"]}, "curves": {"allowed_curve_ids": [ed, ed]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["secp256k1", "ed25519"]}, "curves": {"allowed_curve_ids": [secp, ed]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["Ed25519"]}, "curves": {"allowed_curve_ids": [ed]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519"]}, "curves": {"allowed_curve_ids": [255]}}}),
        norito::json!({"crypto": {"sm": {"allowed_signing": ["ed25519", "secp256k1"]}, "curves": {"allowed_curve_ids": [secp, ed]}}}),
    ] {
        assert!(require_controller(&bytes, &invalid).is_err());
    }
}

#[test]
fn ton_bound_uses_original_stake_retention_minus_the_active_profile_margin() {
    let profiles = SccpChainProfilesV1::genesis();
    let mut epoch = iroha_sccp::light_client::ton::TonEpochV1 {
        key_block_seqno: 1,
        key_block_root_hash: [1; 32],
        validators: iroha_sccp::TonValidatorConfigV1 {
            valid_since: 1,
            valid_until: 2,
            main_validator_count: 0,
            shuffle_masterchain_validators: false,
            validators: vec![],
        },
        stake_held_for: 100_000,
    };
    let set = |epoch| SccpLcConsensusSetV1 {
        set_id: 1,
        valid_from_source_height: 1,
        superseded_at_source_ms: None,
        set_bytes: SccpLcSetDataV1::Ton(epoch).to_frame().unwrap(),
    };
    let client = light_client(SccpNetworkV1::TonMainnet);
    assert_eq!(
        weak_subjectivity_bound(profiles, &client, &set(epoch.clone())).unwrap(),
        100_000_000 - profiles.ton.freshness_margin_ms
    );
    epoch.stake_held_for = 0;
    assert!(weak_subjectivity_bound(profiles, &client, &set(epoch.clone())).is_err());
    epoch.stake_held_for = 100_000;
    epoch.key_block_seqno = 2;
    assert!(weak_subjectivity_bound(profiles, &client, &set(epoch)).is_err());
}
