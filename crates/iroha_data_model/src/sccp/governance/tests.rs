//! Unit tests for the SCCP v1 Parliament governance payload.

use super::*;
use crate::sccp::{
    deployment::{SccpEvmDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1},
    light_client::SccpLightClientParamsError,
    params::SccpParametersError,
    test_support::{assert_rejects_unknown_field, roundtrip},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};

const JSON_MAX: u64 = SCCP_JSON_SAFE_U64_MAX_V1;
const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;
const TAIRA: SccpNetworkV1 = SccpNetworkV1::SoraTaira;

fn network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
        Hash::new([seed; Hash::LENGTH]),
    ))
}

fn account(seed: u8) -> AccountId {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("deterministic Ed25519 seed");
    AccountId::new(key_pair.public_key().clone())
}

fn evm(address: [u8; 20]) -> SccpDeploymentV1 {
    SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
        address,
        runtime_code_hash: [0xc0; 32],
    })
}

fn ton(master_account: [u8; 32]) -> SccpDeploymentV1 {
    let code = |seed: u8| SccpTonCodeRefV1 {
        hash: [seed; 32],
        depth: u16::from(seed),
    };
    SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
        master_account,
        minter_code: code(1),
        wallet_code: code(2),
        bucket_code: code(3),
    })
}

fn register(network: SccpNetworkV1, deployment: SccpDeploymentV1) -> SccpGovernanceActionV1 {
    SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
        network,
        revision: 1,
        deployment,
        max_wrapped_supply: 21_000_000_000_000_000,
    })
}

fn revision(network: SccpNetworkV1, revision: u32) -> SccpRouteRevisionActionV1 {
    SccpRouteRevisionActionV1 { network, revision }
}

fn release(amount: u128, memo: &str) -> SccpGovernanceActionV1 {
    SccpGovernanceActionV1::ReleaseStranded(SccpReleaseStrandedActionV1 {
        network: ETH,
        amount,
        recipient: account(9),
        memo: memo.to_owned(),
    })
}

fn initialize(network: SccpNetworkV1) -> SccpInitializeLightClientActionV1 {
    SccpInitializeLightClientActionV1 {
        network,
        expected: SccpLcInitExpectationV1::Absent,
        params: SccpLightClientParamsV1::defaults_for(network).expect("external network"),
        bootstrap: SccpLcBootstrapV1 {
            network,
            bytes: vec![0x4e, 0x52, 0x54, 0x30, 0x01],
        },
    }
}

fn checkpoint() -> SccpLcCheckpointDataV1 {
    SccpLcCheckpointDataV1 {
        source_height: 21_000_000,
        block_hash: [0x44; 32],
        state_root: Some([0x45; 32]),
        receipts_or_tx_root: [0x46; 32],
        source_time_ms: 1_758_000_000_000,
    }
}

/// One valid action of every kind, in variant order, with pairwise distinct destination words.
fn every_action() -> Vec<SccpGovernanceActionV1> {
    vec![
        register(ETH, evm([0x22; 20])),
        SccpGovernanceActionV1::ActivateRevision(revision(ETH, 1)),
        SccpGovernanceActionV1::SwitchRevision(SccpSwitchRevisionActionV1 {
            network: BSC,
            from: 1,
            to: 2,
        }),
        SccpGovernanceActionV1::DeactivateOutbound(revision(TON, 2)),
        SccpGovernanceActionV1::RetireRevision(revision(TON, 1)),
        SccpGovernanceActionV1::RemoveStaged(revision(TON, 3)),
        release(5_000_000_000, "stranded refund, reviewed in session 12"),
        SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
            network: BSC,
            paused: true,
        }),
        SccpGovernanceActionV1::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
            network: BSC,
            revision: 2,
            paused: true,
        }),
        SccpGovernanceActionV1::InitializeLightClient(initialize(TON)),
        SccpGovernanceActionV1::InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1 {
            network: ETH,
            checkpoint: checkpoint(),
        }),
        SccpGovernanceActionV1::FreezeLightClient(SccpFreezeLightClientActionV1 { network: BSC }),
        SccpGovernanceActionV1::SetParameters(SccpSetParametersActionV1 {
            next: SccpParametersV1::taira_default(),
        }),
        activate_profile(BSC, 2),
    ]
}

fn activate_profile(network: SccpNetworkV1, version: u32) -> SccpGovernanceActionV1 {
    SccpGovernanceActionV1::ActivateLightClientProfile(SccpActivateLightClientProfileActionV1 {
        network,
        version,
        profile_hash: [0x5e; 32],
    })
}

/// Build a proposal for `live` whose `base_revisions` are exactly `S(P)` with revision 0.
fn proposal(actions: Vec<SccpGovernanceActionV1>) -> SccpGovernanceProposalV1 {
    let mut proposal = SccpGovernanceProposalV1 {
        network_id: network_id(1),
        base_revisions: Vec::new(),
        actions,
    };
    proposal.base_revisions = proposal
        .subjects()
        .into_iter()
        .map(|subject| SccpGovernanceBaseRevisionV1 {
            subject,
            revision: 0,
        })
        .collect();
    proposal
}

fn validate(actions: Vec<SccpGovernanceActionV1>) -> Result<(), SccpGovernanceStaticError> {
    proposal(actions).validate_static(&network_id(1))
}

#[test]
fn constants_match_the_spec() {
    assert_eq!(SCCP_GOVERNANCE_MAX_ACTIONS_V1, 16);
    assert_eq!(SCCP_GOVERNANCE_MEMO_MAX_BYTES_V1, 256);
    assert_eq!(SCCP_JSON_SAFE_U64_MAX_V1, 9_007_199_254_740_991);
    assert_eq!(
        SCCP_JSON_SAFE_U64_MAX_V1,
        crate::parliament_types::FIRST_RELEASE_MAX_EXACT_JSON_U64
    );
    assert_eq!(SCCP_TON_MAX_WRAPPED_SUPPLY_EXCLUSIVE_V1, 2_u128.pow(96));
}

#[test]
fn every_action_maps_to_its_spec_subject() {
    let expected = [
        SccpGovernanceSubjectV1::Route(ETH),
        SccpGovernanceSubjectV1::Route(ETH),
        SccpGovernanceSubjectV1::Route(BSC),
        SccpGovernanceSubjectV1::Route(TON),
        SccpGovernanceSubjectV1::Route(TON),
        SccpGovernanceSubjectV1::Route(TON),
        SccpGovernanceSubjectV1::Route(ETH),
        SccpGovernanceSubjectV1::Route(BSC),
        SccpGovernanceSubjectV1::RouteControl(BSC),
        SccpGovernanceSubjectV1::LightClient(TON),
        SccpGovernanceSubjectV1::LightClient(ETH),
        SccpGovernanceSubjectV1::LightClient(BSC),
        SccpGovernanceSubjectV1::Parameters,
        SccpGovernanceSubjectV1::LightClient(BSC),
    ];
    let actions = every_action();
    assert_eq!(actions.len(), expected.len());
    for (action, subject) in actions.iter().zip(expected) {
        assert_eq!(action.subject(), subject, "{action:?}");
    }
}

#[test]
fn action_network_is_the_subject_network() {
    let networks: Vec<_> = every_action()
        .iter()
        .map(SccpGovernanceActionV1::network)
        .collect();
    assert_eq!(
        networks,
        vec![
            Some(ETH),
            Some(ETH),
            Some(BSC),
            Some(TON),
            Some(TON),
            Some(TON),
            Some(ETH),
            Some(BSC),
            Some(BSC),
            Some(TON),
            Some(ETH),
            Some(BSC),
            None,
            Some(BSC),
        ]
    );
}

#[test]
fn subject_order_is_variant_then_value() {
    let mut subjects = vec![
        SccpGovernanceSubjectV1::Parameters,
        SccpGovernanceSubjectV1::LightClient(ETH),
        SccpGovernanceSubjectV1::RouteControl(TON),
        SccpGovernanceSubjectV1::RouteControl(ETH),
        SccpGovernanceSubjectV1::Route(TON),
        SccpGovernanceSubjectV1::Route(BSC),
        SccpGovernanceSubjectV1::Route(ETH),
    ];
    subjects.sort();
    assert_eq!(
        subjects,
        vec![
            SccpGovernanceSubjectV1::Route(ETH),
            SccpGovernanceSubjectV1::Route(BSC),
            SccpGovernanceSubjectV1::Route(TON),
            SccpGovernanceSubjectV1::RouteControl(ETH),
            SccpGovernanceSubjectV1::RouteControl(TON),
            SccpGovernanceSubjectV1::LightClient(ETH),
            SccpGovernanceSubjectV1::Parameters,
        ]
    );
}

#[test]
fn subjects_are_sorted_and_deduplicated() {
    let full = proposal(every_action());
    assert_eq!(
        full.subjects(),
        vec![
            SccpGovernanceSubjectV1::Route(ETH),
            SccpGovernanceSubjectV1::Route(BSC),
            SccpGovernanceSubjectV1::Route(TON),
            SccpGovernanceSubjectV1::RouteControl(BSC),
            SccpGovernanceSubjectV1::LightClient(ETH),
            SccpGovernanceSubjectV1::LightClient(BSC),
            SccpGovernanceSubjectV1::LightClient(TON),
            SccpGovernanceSubjectV1::Parameters,
        ]
    );
    // A pause spans exactly Route{n} and RouteControl{n}.
    let pause = proposal(vec![
        SccpGovernanceActionV1::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
            network: ETH,
            revision: 1,
            paused: true,
        }),
        SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
            network: ETH,
            paused: true,
        }),
        SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
            network: ETH,
            paused: false,
        }),
    ]);
    assert_eq!(
        pause.subjects(),
        vec![
            SccpGovernanceSubjectV1::Route(ETH),
            SccpGovernanceSubjectV1::RouteControl(ETH),
        ]
    );
    assert!(proposal(Vec::new()).subjects().is_empty());
}

#[test]
fn base_revision_from_pair() {
    assert_eq!(
        SccpGovernanceBaseRevisionV1::from((SccpGovernanceSubjectV1::Parameters, 5)),
        SccpGovernanceBaseRevisionV1 {
            subject: SccpGovernanceSubjectV1::Parameters,
            revision: 5,
        }
    );
}

#[test]
fn valid_proposals_pass_static_validation() {
    assert_eq!(validate(every_action()), Ok(()));
    let full: Vec<_> = (0..16)
        .map(|index| {
            SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
                network: ETH,
                paused: index % 2 == 0,
            })
        })
        .collect();
    assert_eq!(validate(full), Ok(()));
    let mut with_revisions = proposal(every_action());
    for (index, entry) in with_revisions.base_revisions.iter_mut().enumerate() {
        entry.revision = u64::try_from(index).expect("small index") * 3;
    }
    assert_eq!(with_revisions.validate_static(&network_id(1)), Ok(()));
}

#[test]
fn network_id_and_action_count_are_checked() {
    assert_eq!(
        proposal(every_action()).validate_static(&network_id(2)),
        Err(SccpGovernanceStaticError::NetworkIdMismatch)
    );
    assert_eq!(
        validate(Vec::new()),
        Err(SccpGovernanceStaticError::NoActions)
    );
    let too_many: Vec<_> = (0..17)
        .map(|_| {
            SccpGovernanceActionV1::FreezeLightClient(SccpFreezeLightClientActionV1 {
                network: ETH,
            })
        })
        .collect();
    assert_eq!(
        validate(too_many),
        Err(SccpGovernanceStaticError::TooManyActions { count: 17 })
    );
}

#[test]
fn taira_is_rejected_in_every_network_bearing_action() {
    let taira_actions = [
        register(TAIRA, evm([0x22; 20])),
        SccpGovernanceActionV1::ActivateRevision(revision(TAIRA, 1)),
        SccpGovernanceActionV1::SwitchRevision(SccpSwitchRevisionActionV1 {
            network: TAIRA,
            from: 1,
            to: 2,
        }),
        SccpGovernanceActionV1::DeactivateOutbound(revision(TAIRA, 1)),
        SccpGovernanceActionV1::RetireRevision(revision(TAIRA, 1)),
        SccpGovernanceActionV1::RemoveStaged(revision(TAIRA, 1)),
        SccpGovernanceActionV1::ReleaseStranded(SccpReleaseStrandedActionV1 {
            network: TAIRA,
            amount: 1,
            recipient: account(9),
            memo: String::new(),
        }),
        SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
            network: TAIRA,
            paused: true,
        }),
        SccpGovernanceActionV1::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
            network: TAIRA,
            revision: 1,
            paused: true,
        }),
        SccpGovernanceActionV1::InitializeLightClient(SccpInitializeLightClientActionV1 {
            network: TAIRA,
            ..initialize(ETH)
        }),
        SccpGovernanceActionV1::InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1 {
            network: TAIRA,
            checkpoint: checkpoint(),
        }),
        SccpGovernanceActionV1::FreezeLightClient(SccpFreezeLightClientActionV1 { network: TAIRA }),
        activate_profile(TAIRA, 2),
    ];
    for action in taira_actions {
        assert_eq!(
            validate(vec![
                SccpGovernanceActionV1::SetParameters(SccpSetParametersActionV1 {
                    next: SccpParametersV1::taira_default(),
                }),
                action.clone()
            ]),
            Err(SccpGovernanceStaticError::TairaNetwork { action: 1 }),
            "{action:?}"
        );
    }
}

#[test]
fn zero_revisions_are_rejected() {
    let mut zero_register = register(ETH, evm([0x22; 20]));
    if let SccpGovernanceActionV1::RegisterRoute(action) = &mut zero_register {
        action.revision = 0;
    }
    let cases = [
        zero_register,
        SccpGovernanceActionV1::ActivateRevision(revision(ETH, 0)),
        SccpGovernanceActionV1::DeactivateOutbound(revision(ETH, 0)),
        SccpGovernanceActionV1::RetireRevision(revision(ETH, 0)),
        SccpGovernanceActionV1::RemoveStaged(revision(ETH, 0)),
        SccpGovernanceActionV1::SwitchRevision(SccpSwitchRevisionActionV1 {
            network: ETH,
            from: 0,
            to: 1,
        }),
        SccpGovernanceActionV1::SwitchRevision(SccpSwitchRevisionActionV1 {
            network: ETH,
            from: 1,
            to: 0,
        }),
        SccpGovernanceActionV1::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
            network: ETH,
            revision: 0,
            paused: false,
        }),
    ];
    for action in cases {
        assert_eq!(
            validate(vec![action.clone()]),
            Err(SccpGovernanceStaticError::ZeroRevision { action: 0 }),
            "{action:?}"
        );
    }
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::SwitchRevision(
            SccpSwitchRevisionActionV1 {
                network: ETH,
                from: 2,
                to: 2,
            }
        )]),
        Err(SccpGovernanceStaticError::SwitchRevisionToSelf { action: 0 })
    );
}

#[test]
fn register_route_cap_and_deployment_are_checked() {
    let with_cap = |network, deployment, cap| {
        SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
            network,
            revision: 1,
            deployment,
            max_wrapped_supply: cap,
        })
    };
    assert_eq!(
        validate(vec![with_cap(ETH, evm([0x22; 20]), 0)]),
        Err(SccpGovernanceStaticError::ZeroMaxWrappedSupply { action: 0 })
    );
    assert_eq!(validate(vec![with_cap(ETH, evm([0x22; 20]), 1)]), Ok(()));
    assert_eq!(
        validate(vec![with_cap(ETH, evm([0x22; 20]), u128::MAX)]),
        Ok(())
    );
    assert_eq!(
        validate(vec![with_cap(BSC, evm([0x22; 20]), u128::MAX)]),
        Ok(())
    );
    assert_eq!(
        validate(vec![with_cap(TON, ton([0x33; 32]), (1 << 96) - 1)]),
        Ok(())
    );
    assert_eq!(
        validate(vec![with_cap(TON, ton([0x33; 32]), 1 << 96)]),
        Err(SccpGovernanceStaticError::TonMaxWrappedSupplyTooLarge { action: 0 })
    );
    for (network, deployment) in [
        (ETH, ton([0x33; 32])),
        (BSC, ton([0x33; 32])),
        (TON, evm([0x22; 20])),
        (ETH, evm([0; 20])),
        (BSC, evm([0; 20])),
        (TON, ton([0; 32])),
    ] {
        assert_eq!(
            validate(vec![with_cap(network, deployment, 1)]),
            Err(SccpGovernanceStaticError::DeploymentNetworkMismatch { action: 0 }),
            "{deployment:?} on {network:?}"
        );
    }
}

#[test]
fn duplicate_destination_words_are_rejected_within_one_proposal() {
    // The same EVM address on Ethereum and BSC has one destination word.
    assert_eq!(
        validate(vec![
            register(ETH, evm([0x22; 20])),
            SccpGovernanceActionV1::FreezeLightClient(SccpFreezeLightClientActionV1 {
                network: ETH,
            }),
            register(BSC, evm([0x22; 20])),
        ]),
        Err(SccpGovernanceStaticError::DuplicateDestinationWord {
            action: 2,
            first: 0,
        })
    );
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&[0x22; 20]);
    assert_eq!(
        validate(vec![
            register(ETH, evm([0x22; 20])),
            register(TON, ton(word))
        ]),
        Err(SccpGovernanceStaticError::DuplicateDestinationWord {
            action: 1,
            first: 0,
        })
    );
    assert_eq!(
        validate(vec![
            register(ETH, evm([0x22; 20])),
            register(BSC, evm([0x23; 20])),
            register(TON, ton([0x25; 32])),
        ]),
        Ok(())
    );
}

#[test]
fn release_stranded_amount_and_memo_are_checked() {
    assert_eq!(
        validate(vec![release(0, "")]),
        Err(SccpGovernanceStaticError::ZeroAmount { action: 0 })
    );
    assert_eq!(validate(vec![release(1, "")]), Ok(()));
    assert_eq!(validate(vec![release(u128::MAX, "")]), Ok(()));
    assert_eq!(validate(vec![release(1, &"m".repeat(256))]), Ok(()));
    assert_eq!(
        validate(vec![release(1, &"m".repeat(257))]),
        Err(SccpGovernanceStaticError::MemoTooLong {
            action: 0,
            len: 257,
        })
    );
    // The bound counts UTF-8 bytes, not characters: 86 three-byte characters are 258 bytes.
    assert_eq!(
        validate(vec![release(1, &"\u{3042}".repeat(86))]),
        Err(SccpGovernanceStaticError::MemoTooLong {
            action: 0,
            len: 258,
        })
    );
}

#[test]
fn initialize_light_client_is_checked() {
    let mut params_mismatch = initialize(ETH);
    params_mismatch.params = SccpLightClientParamsV1::defaults_for(BSC).expect("external");
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(
            params_mismatch
        )]),
        Err(SccpGovernanceStaticError::LightClientParamsNetworkMismatch { action: 0 })
    );

    let mut invalid_params = initialize(ETH);
    invalid_params.params.max_proof_bytes = 0;
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(
            invalid_params
        )]),
        Err(SccpGovernanceStaticError::InvalidLightClientParams {
            action: 0,
            error: SccpLightClientParamsError::ZeroBound {
                field: "max_proof_bytes"
            },
        })
    );

    let mut bootstrap_mismatch = initialize(ETH);
    bootstrap_mismatch.bootstrap.network = BSC;
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(
            bootstrap_mismatch
        )]),
        Err(SccpGovernanceStaticError::BootstrapNetworkMismatch { action: 0 })
    );

    let mut empty = initialize(ETH);
    empty.bootstrap.bytes.clear();
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(empty)]),
        Err(SccpGovernanceStaticError::EmptyBootstrap { action: 0 })
    );

    let mut at_bound = initialize(TON);
    at_bound.bootstrap.bytes = vec![0x5c; SCCP_LC_BOOTSTRAP_MAX_BYTES_V1];
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(
            at_bound.clone()
        )]),
        Ok(())
    );
    let mut over = at_bound;
    over.bootstrap.bytes.push(0);
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(over)]),
        Err(SccpGovernanceStaticError::BootstrapTooLarge {
            action: 0,
            len: SCCP_LC_BOOTSTRAP_MAX_BYTES_V1 + 1,
        })
    );

    let mut unusable = initialize(BSC);
    unusable.expected = SccpLcInitExpectationV1::Unusable;
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::InitializeLightClient(
            unusable
        )]),
        Ok(())
    );
}

#[test]
fn activate_light_client_profile_is_checked() {
    assert_eq!(validate(vec![activate_profile(ETH, 2)]), Ok(()));
    assert_eq!(validate(vec![activate_profile(TON, u32::MAX)]), Ok(()));
    for version in [0, 1] {
        assert_eq!(
            validate(vec![activate_profile(ETH, version)]),
            Err(SccpGovernanceStaticError::GenesisLightClientProfileVersion { action: 0, version })
        );
    }
    let mut zero_hash = activate_profile(BSC, 3);
    if let SccpGovernanceActionV1::ActivateLightClientProfile(action) = &mut zero_hash {
        action.profile_hash = [0; 32];
    }
    assert_eq!(
        validate(vec![zero_hash]),
        Err(SccpGovernanceStaticError::ZeroLightClientProfileHash { action: 0 })
    );
    // It shares the light-client lane subject with initialization, checkpoints and freezes.
    let action = activate_profile(BSC, 2);
    assert_eq!(action.subject(), SccpGovernanceSubjectV1::LightClient(BSC));
    assert_eq!(action.network(), Some(BSC));
    assert_eq!(action.first_json_u64_violation(), None);
    let error = SccpGovernanceStaticError::GenesisLightClientProfileVersion {
        action: 3,
        version: 1,
    };
    assert!(
        error
            .to_string()
            .contains("version 1 is active from genesis")
    );
}

#[test]
fn activate_light_client_profile_has_a_fixed_layout() {
    let action = SccpActivateLightClientProfileActionV1 {
        network: ETH,
        version: 0x0102_0304,
        profile_hash: [0xab; 32],
    };
    roundtrip(&action);
    assert_rejects_unknown_field(&action, &[]);
    let wrapped = SccpGovernanceActionV1::ActivateLightClientProfile(action);
    roundtrip(&wrapped);
    assert_rejects_unknown_field(&wrapped, &["payload"]);
    let value = norito::json::to_value(&wrapped).expect("value");
    assert_eq!(
        value.get("action").and_then(norito::json::Value::as_str),
        Some("activate_light_client_profile")
    );
    // The variant tag is 14, followed by the action's own canonical encoding.
    let encoded = wrapped.encode();
    let bare = action.encode();
    assert!(encoded.ends_with(&bare), "the action body follows the tag");
    assert_eq!(
        <SccpGovernanceActionV1 as norito::codec::DecodeAll>::decode_all(&mut encoded.as_slice())
            .expect("decodes"),
        wrapped
    );
}

#[test]
fn set_parameters_is_checked() {
    let mut next = SccpParametersV1::taira_default();
    next.max_exempt_transactions_per_block = 7;
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::SetParameters(
            SccpSetParametersActionV1 { next }
        )]),
        Err(SccpGovernanceStaticError::InvalidParameters {
            action: 0,
            error: SccpParametersError::ExemptTransactionsOutOfRange,
        })
    );
    next.enabled = false;
    next.max_exempt_transactions_per_block = 8;
    assert_eq!(
        validate(vec![SccpGovernanceActionV1::SetParameters(
            SccpSetParametersActionV1 { next }
        )]),
        Ok(())
    );
}

#[test]
fn base_revisions_must_equal_the_sorted_subject_list() {
    let live = network_id(1);
    let valid = proposal(every_action());
    assert_eq!(valid.validate_static(&live), Ok(()));

    let mut missing = valid.clone();
    missing.base_revisions.pop();
    // A subject no action names, at its sorted position.
    let mut extra = valid.clone();
    assert_eq!(
        extra.base_revisions[3].subject,
        SccpGovernanceSubjectV1::RouteControl(BSC)
    );
    extra.base_revisions.insert(
        4,
        SccpGovernanceBaseRevisionV1 {
            subject: SccpGovernanceSubjectV1::RouteControl(TON),
            revision: 0,
        },
    );
    let mut unsorted = valid.clone();
    unsorted.base_revisions.swap(0, 1);
    let mut duplicated = valid.clone();
    let first = duplicated.base_revisions[0];
    duplicated.base_revisions.insert(0, first);
    let mut wrong_subject = valid.clone();
    wrong_subject.base_revisions[0].subject = SccpGovernanceSubjectV1::RouteControl(ETH);
    let mut empty = valid;
    empty.base_revisions.clear();
    for (name, candidate) in [
        ("missing", missing),
        ("extra", extra),
        ("unsorted", unsorted),
        ("duplicated", duplicated),
        ("wrong subject", wrong_subject),
        ("empty", empty),
    ] {
        assert_eq!(
            candidate.validate_static(&live),
            Err(SccpGovernanceStaticError::BaseRevisionsMismatch),
            "{name}"
        );
    }
}

#[test]
fn json_u64_invariant_is_exact_at_two_to_the_fifty_three() {
    let live = network_id(1);
    let mut at = proposal(every_action());
    for entry in &mut at.base_revisions {
        entry.revision = JSON_MAX;
    }
    assert_eq!(at.first_json_u64_violation(), None);
    assert_eq!(at.validate_static(&live), Ok(()));

    let mut over = at.clone();
    over.base_revisions[3].revision = JSON_MAX + 1;
    let detail = over
        .first_json_u64_violation()
        .expect("base revision violation");
    assert!(detail.contains("base revision"), "{detail}");
    assert_eq!(
        over.validate_static(&live),
        Err(SccpGovernanceStaticError::ExceedsJsonSafeInteger { detail })
    );

    let light_client = |value| {
        let mut action = initialize(ETH);
        action.params.set_retention_ms = value;
        SccpGovernanceActionV1::InitializeLightClient(action)
    };
    let checkpoint_height = |value| {
        let mut data = checkpoint();
        data.source_height = value;
        SccpGovernanceActionV1::InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1 {
            network: ETH,
            checkpoint: data,
        })
    };
    let checkpoint_time = |value| {
        let mut data = checkpoint();
        data.source_time_ms = value;
        SccpGovernanceActionV1::InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1 {
            network: ETH,
            checkpoint: data,
        })
    };
    let parameters = |value| {
        let mut next = SccpParametersV1::taira_default();
        next.committee_validity_ms = value;
        SccpGovernanceActionV1::SetParameters(SccpSetParametersActionV1 { next })
    };
    let builders: [(&str, &dyn Fn(u64) -> SccpGovernanceActionV1); 4] = [
        ("set_retention_ms", &light_client),
        ("source_height", &checkpoint_height),
        ("source_time_ms", &checkpoint_time),
        ("committee_validity_ms", &parameters),
    ];
    for (field, build) in builders {
        let within = proposal(vec![build(JSON_MAX)]);
        assert_eq!(within.first_json_u64_violation(), None, "{field}");
        let beyond = proposal(vec![build(JSON_MAX + 1)]);
        let detail = beyond
            .first_json_u64_violation()
            .unwrap_or_else(|| panic!("{field} at 2^53 must be reported"));
        assert!(detail.contains(field), "{detail} should name {field}");
        assert!(
            beyond.actions[0].first_json_u64_violation().is_some(),
            "{field}"
        );
    }
    // Actions without u64 fields never report a violation.
    for action in every_action() {
        assert_eq!(action.first_json_u64_violation(), None, "{action:?}");
    }
    // Validation reports the JSON bound when no earlier rule catches the value.
    assert_eq!(
        proposal(vec![checkpoint_height(JSON_MAX + 1)]).validate_static(&live),
        Err(SccpGovernanceStaticError::ExceedsJsonSafeInteger {
            detail: "SCCP checkpoint source_height exceeds the exact JSON integer maximum",
        })
    );
    assert_eq!(
        proposal(vec![checkpoint_time(JSON_MAX + 1)]).validate_static(&live),
        Err(SccpGovernanceStaticError::ExceedsJsonSafeInteger {
            detail: "SCCP checkpoint source_time_ms exceeds the exact JSON integer maximum",
        })
    );
    // A parameter above the bound breaks its own table rule first.
    assert_eq!(
        proposal(vec![parameters(JSON_MAX + 1)]).validate_static(&live),
        Err(SccpGovernanceStaticError::InvalidParameters {
            action: 0,
            error: SccpParametersError::CommitteeValidityTooLong,
        })
    );
}

#[test]
fn every_type_roundtrips_through_binary_and_json() {
    for action in every_action() {
        roundtrip(&action);
        roundtrip(&action.subject());
    }
    roundtrip(&SccpGovernanceSubjectV1::Parameters);
    roundtrip(&SccpGovernanceBaseRevisionV1 {
        subject: SccpGovernanceSubjectV1::LightClient(TON),
        revision: JSON_MAX,
    });
    roundtrip(&register(TON, ton([0x33; 32])));
    roundtrip(&register(BSC, evm([0x34; 20])));
    roundtrip(&release(u128::MAX, "\u{3042} memo"));
    let mut proposal = proposal(every_action());
    proposal.base_revisions[0].revision = 11;
    roundtrip(&proposal);
    roundtrip(&SccpGovernanceProposalV1 {
        network_id: network_id(7),
        base_revisions: Vec::new(),
        actions: Vec::new(),
    });
}

#[test]
fn proposal_json_is_closed_and_amounts_are_decimal_strings() {
    let proposal = proposal(vec![
        register(ETH, evm([0x22; 20])),
        release(u128::MAX, "memo"),
    ]);
    assert_rejects_unknown_field(&proposal, &[]);
    assert_rejects_unknown_field(&proposal.actions[0], &[]);
    assert_rejects_unknown_field(&proposal.base_revisions[0], &[]);
    let json = norito::json::to_json(&proposal).expect("serialize");
    assert!(
        json.contains(r#""max_wrapped_supply":"21000000000000000""#),
        "{json}"
    );
    assert!(
        json.contains(r#""amount":"340282366920938463463374607431768211455""#),
        "{json}"
    );
}

#[test]
fn unknown_action_and_subject_tags_are_rejected() {
    // 13 was the bridge-key fault clearing; it stays unassigned.
    for unsupported_tag in [13_u32, 15, 16, u32::MAX] {
        let mut encoded = unsupported_tag.encode();
        encoded.extend_from_slice(&[0x11; 256]);
        assert!(
            <SccpGovernanceActionV1 as norito::codec::DecodeAll>::decode_all(
                &mut encoded.as_slice()
            )
            .is_err(),
            "action tag {unsupported_tag} unexpectedly decoded"
        );
    }
    // 4 was the bridge-key fault subject; it stays unassigned.
    for unsupported_tag in [4_u32, 5, u32::MAX] {
        let mut encoded = unsupported_tag.encode();
        encoded.extend_from_slice(&[0x11; 64]);
        assert!(
            <SccpGovernanceSubjectV1 as norito::codec::DecodeAll>::decode_all(
                &mut encoded.as_slice()
            )
            .is_err(),
            "subject tag {unsupported_tag} unexpectedly decoded"
        );
    }
}

#[test]
fn clear_bridge_key_fault_and_its_subject_do_not_decode() {
    // The JSON tags of the retired action and subject are refused, with any payload.
    let subject = norito::json::to_json(&SccpGovernanceSubjectV1::Route(ETH)).expect("json");
    assert!(subject.contains(r#""subject":"route""#), "{subject}");
    let retired_subject =
        subject.replace(r#""subject":"route""#, r#""subject":"bridge_key_fault""#);
    assert!(norito::json::from_json::<SccpGovernanceSubjectV1>(&retired_subject).is_err());
    let action = norito::json::to_json(&SccpGovernanceActionV1::FreezeLightClient(
        SccpFreezeLightClientActionV1 { network: ETH },
    ))
    .expect("json");
    assert!(
        action.contains(r#""action":"freeze_light_client""#),
        "{action}"
    );
    let retired_action = action.replace(
        r#""action":"freeze_light_client""#,
        r#""action":"clear_bridge_key_fault""#,
    );
    assert!(norito::json::from_json::<SccpGovernanceActionV1>(&retired_action).is_err());
    for payload in ["{}", r#"{"peer":"x","fault":{"address":"00","height":1}}"#] {
        let json = format!(r#"{{"action":"clear_bridge_key_fault","payload":{payload}}}"#);
        assert!(
            norito::json::from_json::<SccpGovernanceActionV1>(&json).is_err(),
            "{json}"
        );
    }
    // Every action that survives keeps its codec index: the freed 13 is a hole, not a shift.
    let actions = every_action();
    let indices: [u32; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14];
    assert_eq!(actions.len(), indices.len());
    for (action, index) in actions.iter().zip(indices) {
        assert!(action.encode().starts_with(&index.encode()), "{action:?}");
    }
    for (subject, index) in [
        SccpGovernanceSubjectV1::Route(ETH),
        SccpGovernanceSubjectV1::RouteControl(ETH),
        SccpGovernanceSubjectV1::LightClient(ETH),
        SccpGovernanceSubjectV1::Parameters,
    ]
    .iter()
    .zip(0_u32..)
    {
        assert!(subject.encode().starts_with(&index.encode()), "{subject:?}");
    }
}

#[test]
fn register_route_names_no_committee_until_the_pin_lands() {
    // TODO: WP-S4: replace with the `initial_committee` pin checks (§4.14.3 P1 to P5).
    let action = register(ETH, evm([0x22; 20]));
    let mut value = norito::json::to_value(&action).expect("value");
    let payload = value
        .as_object_mut()
        .expect("action object")
        .get_mut("payload")
        .and_then(norito::json::Value::as_object_mut)
        .expect("payload object");
    let fields: Vec<&str> = payload.keys().map(String::as_str).collect();
    assert_eq!(
        fields,
        ["deployment", "max_wrapped_supply", "network", "revision"]
    );
    assert_eq!(action.first_json_u64_violation(), None);
    // The retired roster pin is not a field of the action.
    payload.insert(
        "initial_roster_generation".to_owned(),
        norito::json::Value::from(7_u64),
    );
    let hostile = norito::json::to_json(&value).expect("json");
    assert!(norito::json::from_json::<SccpGovernanceActionV1>(&hostile).is_err());
}

#[test]
fn static_errors_render_their_context() {
    let error = SccpGovernanceStaticError::MemoTooLong {
        action: 2,
        len: 300,
    };
    assert_eq!(
        error.to_string(),
        "action 2 memo has 300 bytes; at most 256 are allowed"
    );
    let nested = SccpGovernanceStaticError::InvalidParameters {
        action: 0,
        error: SccpParametersError::CommitteeHeartbeatTooShort,
    };
    assert!(nested.to_string().contains("committee_heartbeat_ms"));
}

#[test]
fn trusted_checkpoints_are_refused_for_ton() {
    let install = |network| {
        SccpGovernanceActionV1::InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1 {
            network,
            checkpoint: checkpoint(),
        })
    };
    for network in [ETH, BSC] {
        assert_eq!(validate(vec![install(network)]), Ok(()));
    }
    assert_eq!(
        validate(vec![
            SccpGovernanceActionV1::FreezeLightClient(SccpFreezeLightClientActionV1 {
                network: ETH
            }),
            install(TON),
        ]),
        Err(SccpGovernanceStaticError::TonTrustedCheckpoint { action: 1 })
    );
    assert!(
        SccpGovernanceStaticError::TonTrustedCheckpoint { action: 1 }
            .to_string()
            .contains("reads none")
    );
}
