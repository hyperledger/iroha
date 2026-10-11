//! Rust-authored first-release validator and staking SDK codec fixtures.
//!
//! These rows pin DTO wire shape only. Cryptographic and committee activation
//! validity is exercised by Core and disposable-network qualification.

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature, SignatureOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetId,
    block::BlockHeader,
    consensus::{
        GLOBAL_THRESHOLD_BEACON_VERSION_V1, GlobalThresholdBeaconDkgConstantProofV1,
        GlobalThresholdBeaconDkgDealerCommitmentV1, GlobalThresholdBeaconDkgEncryptedShareV1,
        GlobalThresholdBeaconDkgRecipientKeyV1, GlobalThresholdBeaconDkgSessionV1,
        GlobalThresholdBeaconDkgShareAcceptanceV1, GlobalThresholdBeaconDkgTranscriptV1,
    },
    isi::staking::{PublicLanePeerBindingAuthorization, RebindPublicLaneValidatorPeer},
    nexus::{
        PublicLaneFeeRewardClaimV1, PublicLaneMonetaryBondV1, PublicLaneMonetaryPlanV1,
        PublicLaneMonetaryPreconditionV1, PublicLaneMonetaryRegistrationV1,
        PublicLaneMonetaryScopeV1, PublicLaneMonetarySlashV1, PublicLaneMonetaryUnbondV1,
        PublicLanePreparationBalanceV1, PublicLanePreparationOperationV1,
        PublicLanePreparationRequestV1, PublicLanePreparationV1, PublicLanePrepareBondV1,
        PublicLanePrepareClaimV1, PublicLanePrepareRegistrationV1, PublicLanePrepareUnbondV1,
        PublicLanePreparedPlanV1, PublicLaneRewardClaimPlanV1, ValidatorCommitteeCredentialsV1,
        ValidatorCommitteePreparationV1, ValidatorCommitteeTransitionV1,
    },
    parameter::system::SumeragiNposParameters,
    sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochAuthorizationV1,
        ValidatorEpochDecisionV1, ValidatorGenerationV1,
    },
};
use iroha_model_base::{peer::PeerId, topology::LaneId};
use iroha_primitives::numeric::Quantity;
use norito::codec::{DecodeAll, Encode};

fn key(seed: u8, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], algorithm).expect("deterministic checked key")
}

fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"validator-staking-sdk-wire-v1",
    )))
}

fn peers() -> Vec<PeerId> {
    let mut peers = (1_u8..=4)
        .map(|seed| PeerId::new(key(seed, Algorithm::BlsNormal).public_key().clone()))
        .collect::<Vec<_>>();
    peers.sort();
    peers
}

fn generation(network_id: NetworkId, peers: &[PeerId], generation: u64) -> ValidatorGenerationV1 {
    ValidatorGenerationV1 {
        network_id,
        generation,
        validators: peers.to_vec(),
    }
}

fn dkg_session(network_id: NetworkId) -> GlobalThresholdBeaconDkgSessionV1 {
    GlobalThresholdBeaconDkgSessionV1 {
        version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        network_id,
        session_id: [0x31; 32],
        attempt_id: [0x32; 32],
        authority_generation: 1,
        roster_hash: [0x33; 32],
        committee_size: 4,
        threshold: 2,
        start_height: 101,
        commitments_end_height: 111,
        deliveries_end_height: 121,
        acceptances_end_height: 131,
    }
}

fn dkg_transcript(
    session: GlobalThresholdBeaconDkgSessionV1,
    peers: &[PeerId],
) -> GlobalThresholdBeaconDkgTranscriptV1 {
    let signature = Signature::from_bytes(&[0x42; 96]);
    let recipient_keys = peers
        .iter()
        .enumerate()
        .map(
            |(index, validator)| GlobalThresholdBeaconDkgRecipientKeyV1 {
                recipient_index: u16::try_from(index + 1).unwrap(),
                validator: validator.clone(),
                x25519_public_key: [u8::try_from(index + 1).unwrap(); 32],
                mlkem768_public_key: vec![u8::try_from(index + 7).unwrap(); 1184],
                signature: signature.clone(),
            },
        )
        .collect::<Vec<_>>();
    let dealer_commitments = (1_u16..=4)
        .map(|dealer_index| GlobalThresholdBeaconDkgDealerCommitmentV1 {
            dealer_index,
            coefficient_commitments: vec![[u8::try_from(dealer_index).unwrap() + 0x10; 96]; 2],
            constant_term_proof: GlobalThresholdBeaconDkgConstantProofV1 {
                commitment: [u8::try_from(dealer_index).unwrap() + 0x20; 96],
                response: [u8::try_from(dealer_index).unwrap() + 0x30; 32],
            },
            signature: signature.clone(),
        })
        .collect::<Vec<_>>();
    let mut encrypted_shares = Vec::new();
    let mut share_acceptances = Vec::new();
    for dealer_index in 1_u16..=4 {
        for recipient_index in 1_u16..=4 {
            encrypted_shares.push(GlobalThresholdBeaconDkgEncryptedShareV1 {
                dealer_index,
                recipient_index,
                dealer_commitment_hash: [u8::try_from(dealer_index).unwrap(); 32],
                recipient_key_hash: [u8::try_from(recipient_index).unwrap(); 32],
                delivery_height: 120,
                ephemeral_x25519_public_key: [0x51; 32],
                mlkem768_ciphertext: vec![0x52; 1088],
                encrypted_share: vec![0x53; 128],
                signature: signature.clone(),
            });
            share_acceptances.push(GlobalThresholdBeaconDkgShareAcceptanceV1 {
                dealer_index,
                recipient_index,
                dealer_commitment_hash: [u8::try_from(dealer_index).unwrap(); 32],
                encrypted_share_hash: [0x54; 32],
                accepted_height: 130,
                signature: signature.clone(),
            });
        }
    }
    GlobalThresholdBeaconDkgTranscriptV1 {
        session,
        generator_h: [0x55; 96],
        generator_v: [0x56; 96],
        dealer_commitments,
        recipient_keys,
        encrypted_shares,
        share_acceptances,
        qualified_dealers: vec![1, 2, 3, 4],
        event_hash: [0x57; 32],
        finalized_at_height: 131,
    }
}

fn all_fixture_rows() -> Vec<(&'static str, Vec<u8>)> {
    let network_id = network();
    let peers = peers();
    let genesis_generation = generation(network_id, &peers, 0);
    let successor_generation = generation(network_id, &peers, 1);
    let genesis_authorization = ValidatorEpochAuthorizationV1 {
        version: 1,
        network_id,
        epoch: 0,
        first_height: 1,
        last_height: 100,
        authority_generation: 0,
        authority_id: genesis_generation.generation_id().unwrap(),
        beacon: BeaconEpochBindingV1::Bootstrap,
        previous_authorization_id: [0; 32],
        transition_id: [0; 32],
        decision: ValidatorEpochDecisionV1::Genesis,
    };
    let session = dkg_session(network_id);
    let transcript = dkg_transcript(session, &peers);
    let installed = InstalledBeaconEpochBindingV1 {
        session_id: session.session_id,
        transcript_hash: [0x58; 32],
    };
    let activation = ValidatorEpochAuthorizationV1 {
        version: 1,
        network_id,
        epoch: 2,
        first_height: 201,
        last_height: 300,
        authority_generation: 1,
        authority_id: successor_generation.generation_id().unwrap(),
        beacon: BeaconEpochBindingV1::Installed(installed),
        previous_authorization_id: [0x59; 32],
        transition_id: [0x5a; 32],
        decision: ValidatorEpochDecisionV1::Activate,
    };
    let preparation = ValidatorCommitteePreparationV1 {
        version: 1,
        network_id,
        selection_epoch: 0,
        selection_height: 100,
        selection_anchor: HashOf::from_untyped_unchecked(Hash::new(b"sdk-selection-anchor")),
        target_epoch: 2,
        first_height: 201,
        last_height: 300,
        authority_generation: 1,
        preparing_authorization_id: [0x61; 32],
        election_seed: [0x62; 32],
        eligibility: iroha_data_model::nexus::ValidatorElectionPolicyV1 {
            epoch_length_blocks: 100,
            ..iroha_data_model::nexus::ValidatorElectionPolicyV1::from_npos_parameters(
                &iroha_data_model::parameter::system::SumeragiNposParameters::default(),
            )
            .unwrap()
        },
        committee: peers
            .iter()
            .map(|peer| {
                let key = (1_u8..=4)
                    .map(|seed| key(seed, Algorithm::BlsNormal))
                    .find(|key| key.public_key() == peer.public_key())
                    .unwrap();
                iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1 {
                    validator: peer.clone(),
                    proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .unwrap(),
                }
            })
            .collect(),
    };
    preparation
        .validate()
        .expect("real frozen committee and policy");
    assert_eq!(preparation.generation(), successor_generation);
    let transition = ValidatorCommitteeTransitionV1 {
        preparation,
        credentials: Some(ValidatorCommitteeCredentialsV1 { beacon: installed }),
        readiness: Vec::new(),
        outcome: Some(activation),
    };
    let staker = AccountId::new(key(0x71, Algorithm::Ed25519).public_key().clone());
    let custody = AccountId::new(key(0x72, Algorithm::Ed25519).public_key().clone());
    let xor = SumeragiNposParameters::default()
        .xor_asset_definition_id()
        .clone();
    let plan = PublicLaneMonetaryPlanV1 {
        network_scope: PublicLaneMonetaryScopeV1::Network(network_id),
        valid_until_height: 210,
        source_asset: AssetId::new(xor.clone(), staker.clone()),
        destination_asset: AssetId::new(xor, custody),
        amount: Quantity::from(1000_u64),
        precondition: PublicLaneMonetaryPreconditionV1::Registration(
            PublicLaneMonetaryRegistrationV1 {
                activation_height: 201,
            },
        ),
    };
    let bond_plan = PublicLaneMonetaryPlanV1 {
        precondition: PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
            activation_height: 201,
            peer_id: peers[0].clone(),
        }),
        ..plan.clone()
    };
    let unbond_plan = PublicLaneMonetaryPlanV1 {
        source_asset: plan.destination_asset.clone(),
        destination_asset: plan.source_asset.clone(),
        precondition: PublicLaneMonetaryPreconditionV1::Unbond(PublicLaneMonetaryUnbondV1 {
            activation_height: 201,
            request_hash: Hash::prehashed([0x75; 32]),
        }),
        ..plan.clone()
    };
    // These are exact DTO layouts; a privileged slash's authority and designated
    // sink are authenticated by native execution, not by this wire fixture.
    let slash_plan = PublicLaneMonetaryPlanV1 {
        source_asset: plan.destination_asset.clone(),
        destination_asset: plan.source_asset.clone(),
        precondition: PublicLaneMonetaryPreconditionV1::Slash(PublicLaneMonetarySlashV1 {
            activation_height: 201,
            slashable_exposure: Quantity::from(1500_u64),
        }),
        ..plan.clone()
    };
    let fee_reward_plan = PublicLaneRewardClaimPlanV1 {
        network_scope: PublicLaneMonetaryScopeV1::Network(network_id),
        valid_until_height: 210,
        fee_claim: PublicLaneFeeRewardClaimV1 {
            lifecycle_seal: [0x77; 32],
            beneficiary_id: staker.clone(),
            beneficiary_revision: 4,
            source_asset: plan.destination_asset.clone(),
            destination_asset: plan.source_asset.clone(),
            amount: Quantity::from(7_u64),
            expected_claim_sequence: 5,
        },
    };
    assert!(fee_reward_plan.has_canonical_shape(&staker));
    let new_peer_key = key(0x73, Algorithm::Ed25519);
    let new_peer = PeerId::new(new_peer_key.public_key().clone());
    let consent = PublicLanePeerBindingAuthorization::new(
        network_id,
        LaneId::SINGLE,
        staker.clone(),
        new_peer.clone(),
        201,
        peers[0].clone(),
    );
    let rebind = RebindPublicLaneValidatorPeer::new(
        LaneId::SINGLE,
        staker.clone(),
        new_peer,
        SignatureOf::try_new(new_peer_key.private_key(), &consent).unwrap(),
    );
    let mut rows = vec![
        ("validator_generation", genesis_generation.encode()),
        ("epoch_authorization", genesis_authorization.encode()),
        ("dkg_session", session.encode()),
        ("dkg_transcript", transcript.encode()),
        ("committee_transition", transition.encode()),
        ("monetary_plan", plan.encode()),
        ("monetary_bond_plan", bond_plan.encode()),
        ("monetary_unbond_plan", unbond_plan.encode()),
        ("monetary_slash_plan", slash_plan.encode()),
        ("fee_reward_claim_plan", fee_reward_plan.encode()),
        ("rebind_peer", rebind.encode()),
    ];
    let requests = [
        (
            "prepare_registration_request",
            "prepare_registration_response",
            PublicLanePreparationOperationV1::Registration(PublicLanePrepareRegistrationV1 {
                validator: staker.clone(),
                peer_id: peers[0].clone(),
                amount: plan.amount.clone(),
                candidate: true,
            }),
            PublicLanePreparedPlanV1::Monetary(plan.clone()),
        ),
        (
            "prepare_bond_request",
            "prepare_bond_response",
            PublicLanePreparationOperationV1::Bond(PublicLanePrepareBondV1 {
                validator: staker.clone(),
                staker: staker.clone(),
                amount: bond_plan.amount.clone(),
            }),
            PublicLanePreparedPlanV1::Monetary(bond_plan),
        ),
        (
            "prepare_unbond_request",
            "prepare_unbond_response",
            PublicLanePreparationOperationV1::FinalizeUnbond(PublicLanePrepareUnbondV1 {
                validator: staker.clone(),
                staker: staker.clone(),
                request_id: Hash::new(b"sdk-withdrawal-request"),
            }),
            PublicLanePreparedPlanV1::Monetary(unbond_plan),
        ),
        (
            "prepare_claim_request",
            "prepare_claim_response",
            PublicLanePreparationOperationV1::ClaimRewards(PublicLanePrepareClaimV1 {
                recipient: staker,
            }),
            PublicLanePreparedPlanV1::Claim(fee_reward_plan),
        ),
    ];
    for (request_name, response_name, operation, prepared_plan) in requests {
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 10,
            operation,
        };
        let assets: std::collections::BTreeSet<_> =
            [plan.source_asset.clone(), plan.destination_asset.clone()]
                .into_iter()
                .collect();
        let response = PublicLanePreparationV1 {
            request: request.clone(),
            network_id,
            observed_height: 200,
            observed_block_hash: Hash::new(b"sdk-preparation-observation"),
            observed_ledger_time_ms: 20_000,
            assumed_execution_height: 201,
            xor_asset_definition_id: plan.source_asset.definition().clone(),
            plan: prepared_plan,
            balances: assets
                .into_iter()
                .map(|asset| PublicLanePreparationBalanceV1 {
                    asset,
                    balance: Quantity::from(5_000_u64),
                    stake_reserved: Quantity::from(1_000_u64),
                    rewards_reserved: Quantity::from(22_u64),
                })
                .collect(),
        };
        rows.push((request_name, norito::encode_canonical(&request).unwrap()));
        rows.push((response_name, norito::encode_canonical(&response).unwrap()));
    }
    rows
}

// Bare DTO payload fixtures stay separate from full request/response frames.
// SDK consumers decode only the current first-release DTO identities.
fn fixture_rows() -> Vec<(&'static str, Vec<u8>)> {
    all_fixture_rows()
        .into_iter()
        .filter(|(name, _)| !name.starts_with("prepare_"))
        .collect()
}

fn preparation_fixture_rows() -> Vec<(&'static str, Vec<u8>)> {
    all_fixture_rows()
        .into_iter()
        .filter(|(name, _)| name.starts_with("prepare_"))
        .collect()
}

#[test]
fn operation_specific_monetary_fixtures_roundtrip_exact_bindings_and_network_xor() {
    let xor = SumeragiNposParameters::default()
        .xor_asset_definition_id()
        .clone();
    let rows = fixture_rows();
    let plans = rows
        .iter()
        .filter(|(kind, _)| kind.starts_with("monetary_"))
        .map(|(kind, bytes)| {
            let plan = PublicLaneMonetaryPlanV1::decode_all(&mut bytes.as_slice()).unwrap();
            assert_eq!(plan.encode(), *bytes, "{kind} exact roundtrip");
            assert_eq!(
                plan.network_scope,
                PublicLaneMonetaryScopeV1::Network(network())
            );
            assert_eq!(plan.valid_until_height, 210);
            assert_eq!(plan.amount, Quantity::from(1000_u64));
            for asset in [&plan.source_asset, &plan.destination_asset] {
                assert_eq!(asset.definition(), &xor);
                assert_eq!(asset, &AssetId::new(xor.clone(), asset.account().clone()));
            }
            (*kind, plan)
        })
        .collect::<Vec<_>>();
    assert_eq!(plans.len(), 4);
    let registration = &plans[0].1;
    for (kind, plan) in &plans {
        match &plan.precondition {
            PublicLaneMonetaryPreconditionV1::Registration(value) => {
                assert_eq!(*kind, "monetary_plan");
                assert_eq!(value.activation_height, 201);
            }
            PublicLaneMonetaryPreconditionV1::Bond(value) => {
                assert_eq!(*kind, "monetary_bond_plan");
                assert_eq!(value.activation_height, 201);
                assert_eq!(value.peer_id, peers()[0]);
                assert_eq!(plan.source_asset, registration.source_asset);
                assert_eq!(plan.destination_asset, registration.destination_asset);
            }
            PublicLaneMonetaryPreconditionV1::Unbond(value) => {
                assert_eq!(*kind, "monetary_unbond_plan");
                assert_eq!(value.activation_height, 201);
                assert_eq!(value.request_hash, Hash::prehashed([0x75; 32]));
                assert_eq!(plan.source_asset, registration.destination_asset);
                assert_eq!(plan.destination_asset, registration.source_asset);
            }
            PublicLaneMonetaryPreconditionV1::Slash(value) => {
                assert_eq!(*kind, "monetary_slash_plan");
                assert_eq!(value.activation_height, 201);
                assert_eq!(value.slashable_exposure, Quantity::from(1500_u64));
                assert_eq!(plan.source_asset, registration.destination_asset);
                assert_eq!(plan.destination_asset, registration.source_asset);
            }
        }
    }
}

#[test]
fn staking_preparation_frames_keep_schema_alignment_and_exact_native_intent() {
    let rows = preparation_fixture_rows();
    let frames = rows.iter().collect::<Vec<_>>();
    assert_eq!(frames.len(), 8);
    for (name, bytes) in frames {
        assert_eq!(&bytes[..4], b"NRT0");
        if name.ends_with("_request") {
            let request =
                norito::decode_canonical::<PublicLanePreparationRequestV1>(bytes).unwrap();
            assert_eq!(norito::encode_canonical(&request).unwrap(), *bytes);
            assert!(
                bytes.len() <= iroha_data_model::nexus::PUBLIC_LANE_PREPARATION_REQUEST_MAX_BYTES
            );
            assert_eq!(request.lane_id, LaneId::SINGLE);
            assert_eq!(request.valid_for_blocks, 10);
        } else {
            let response = norito::decode_canonical::<PublicLanePreparationV1>(bytes).unwrap();
            assert_eq!(norito::encode_canonical(&response).unwrap(), *bytes);
            assert!(
                bytes.len() <= iroha_data_model::nexus::PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES
            );
            assert_eq!(response.network_id, network());
            assert_eq!(
                response.observed_height + 1,
                response.assumed_execution_height
            );
            assert_eq!(
                response.xor_asset_definition_id,
                SumeragiNposParameters::default()
                    .xor_asset_definition_id()
                    .clone()
            );
            for row in response.balances {
                assert_eq!(
                    row.asset,
                    AssetId::new(
                        response.xor_asset_definition_id.clone(),
                        row.asset.account().clone()
                    )
                );
                assert_eq!(row.stake_reserved, Quantity::from(1_000_u64));
                assert_eq!(row.rewards_reserved, Quantity::from(22_u64));
            }
        }
    }
}

#[test]
fn retired_synthetic_xor_has_the_same_rejected_sdk_identity() {
    let retired = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("nexus.universal").unwrap(),
        "xor".parse().unwrap(),
    );
    assert_eq!(
        hex::encode(retired.aid_bytes()),
        "5ecd1e80ac7d4d18b22772091a73fc13"
    );
    assert_ne!(
        retired,
        SumeragiNposParameters::default()
            .xor_asset_definition_id()
            .clone()
    );
}

#[test]
fn committed_validator_staking_sdk_fixtures_match_current_rust_records() {
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/validator_staking/norito_v1.tsv"
    ))
    .expect("read canonical validator-staking fixture");
    let rows = committed
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('\t').expect("kind and canonical hex"))
        .collect::<Vec<_>>();
    let expected = fixture_rows();
    assert_eq!(rows.len(), expected.len(), "fixture row count changed");
    for ((kind, bytes), (committed_kind, committed_hex)) in expected.into_iter().zip(rows) {
        assert_eq!(committed_kind, kind, "fixture order or identity changed");
        assert_eq!(
            committed_hex,
            hex::encode(bytes),
            "{kind} Norito bytes drifted"
        );
    }
}

#[test]
#[ignore = "regenerate fixtures/validator_staking/norito_v1.tsv after source model changes"]
fn print_validator_staking_sdk_fixtures() {
    for (kind, bytes) in fixture_rows() {
        println!(
            "VALIDATOR_STAKING_SDK_FIXTURE={kind}\t{}",
            hex::encode(bytes)
        );
    }
}

#[test]
fn committed_staking_preparation_sdk_fixtures_match_current_rust_frames() {
    // Read at runtime so the ignored native producer can run before first capture.
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/validator_staking/preparation_v1.tsv"
    )).expect("missing native preparation fixtures; run print_staking_preparation_sdk_fixtures and capture its actual rows");
    let rows = committed
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('\t').expect("kind and canonical hex"))
        .collect::<Vec<_>>();
    let expected = preparation_fixture_rows();
    assert_eq!(
        rows.len(),
        expected.len(),
        "preparation fixture row count changed"
    );
    for ((kind, bytes), (committed_kind, committed_hex)) in expected.into_iter().zip(rows) {
        assert_eq!(
            committed_kind, kind,
            "preparation fixture order or identity changed"
        );
        assert_eq!(
            committed_hex,
            hex::encode(bytes),
            "{kind} Norito frame drifted"
        );
    }
}

#[test]
#[ignore = "capture actual native frames into fixtures/validator_staking/preparation_v1.tsv"]
fn print_staking_preparation_sdk_fixtures() {
    for (kind, bytes) in preparation_fixture_rows() {
        println!(
            "STAKING_PREPARATION_SDK_FIXTURE={kind}\t{}",
            hex::encode(bytes)
        );
    }
}
