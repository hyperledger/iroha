//! Causal original-effect binding with genuine native TON proofs.

use super::*;
use iroha_data_model::sccp::light_client::{SccpLcInitExpectationV1, SccpLightClientParamsV1};
use iroha_sccp::{
    light_client::{
        initialize_light_client_with_profiles,
        profile::SccpChainProfilesV1,
        proof::{SccpNormalizedEventV1, SccpSourceProofV1},
        state::SccpLcMemoryStateV1,
        ton::{TonMasterchainAnchorV1, TonSourceProofV1},
        verify_proof_with_profiles,
    },
    test_support::ton::{SyntheticTonChainV1, SyntheticTonEventV1},
};
use iroha_sccp_rpc::builders::{SourceEventRefV1, SourceEvidenceV1};

fn genuine(
    event: SyntheticTonEventV1,
) -> (
    SccpNormalizedEventV1,
    SourceEvidenceV1,
    SourceEventRefV1,
    iroha_sccp::light_client::state::SccpLcInitialStateV1,
) {
    let chain = SyntheticTonChainV1::new([72; 32]);
    let profiles = SccpChainProfilesV1::genesis();
    let time = 1_790_000_000;
    let now = (u64::from(time) + 2_000) * 1000;
    let network = SccpNetworkV1::TonMainnet;
    let mut state = SccpLcMemoryStateV1::new();
    let initial = initialize_light_client_with_profiles(
        profiles,
        &state,
        network,
        SccpLcInitExpectationV1::Absent,
        &SccpLightClientParamsV1::defaults_for(network).unwrap(),
        &chain.bootstrap(100, 0, time, time + 65536),
        now,
    )
    .unwrap();
    state.install(network, &initial);
    let minter = [9; 32];
    let block = chain.shard_block(
        10,
        &chain.genesis_shard(),
        &chain.genesis_shard(),
        &minter,
        Some(&(500, event, true)),
    );
    let (master, _) = chain.master_block(150, 100, 0, time + 500, &block.link.block_id, &[], 4);
    let transaction = block.transaction.unwrap();
    let hash = iroha_sccp::ton_canonical_boc_single_root_hash_v1(&transaction).unwrap();
    let proof = SccpSourceProofV1::Ton(TonSourceProofV1 {
        masterchain: TonMasterchainAnchorV1::Signed(master),
        shard_blocks: vec![block.link.clone()],
        event_block_proof: block.link.header_proof,
        transaction,
        transaction_lt: 500,
        message_index: 0,
        minter,
    })
    .to_bytes()
    .unwrap();
    let event = verify_proof_with_profiles(profiles, &state, network, &proof, now)
        .unwrap()
        .event;
    (
        event,
        SourceEvidenceV1 {
            backfills: vec![],
            proof,
        },
        SourceEventRefV1::Ton {
            minter,
            lt: 500,
            hash,
            message_index: 0,
        },
        initial,
    )
}

#[test]
fn genuine_ton_effect_requires_exact_original_transaction_and_intent() {
    use iroha_sccp::ton_watch::TerminalEvent;
    let (event, proof, reference, _) = genuine(SyntheticTonEventV1::Finalized {
        message_id: [7; 32],
        nonce: 19,
    });
    super::super::require_ton_reference(&reference, &proof).unwrap();
    require_ton_terminal(
        &event,
        [9; 32],
        TerminalEvent::Finalized {
            message_id: [7; 32],
            nonce: 19,
        },
    )
    .unwrap();
    for variant in 0..4 {
        let SourceEventRefV1::Ton {
            minter,
            lt,
            hash,
            message_index,
        } = &reference
        else {
            unreachable!()
        };
        let mut other = SourceEventRefV1::Ton {
            minter: *minter,
            lt: *lt,
            hash: *hash,
            message_index: *message_index,
        };
        if let SourceEventRefV1::Ton {
            minter,
            lt,
            hash,
            message_index,
        } = &mut other
        {
            match variant {
                0 => minter[0] ^= 1,
                1 => *lt += 1,
                2 => hash[0] ^= 1,
                _ => *message_index += 1,
            }
        }
        assert!(super::super::require_ton_reference(&other, &proof).is_err());
    }
    assert!(
        require_ton_terminal(
            &event,
            [8; 32],
            TerminalEvent::Finalized {
                message_id: [7; 32],
                nonce: 19
            }
        )
        .is_err()
    );
    assert!(
        require_ton_terminal(
            &event,
            [9; 32],
            TerminalEvent::Finalized {
                message_id: [8; 32],
                nonce: 19
            }
        )
        .is_err()
    );
    assert!(
        require_ton_terminal(
            &event,
            [9; 32],
            TerminalEvent::Finalized {
                message_id: [7; 32],
                nonce: 20
            }
        )
        .is_err()
    );
    assert!(
        require_ton_terminal(
            &event,
            [9; 32],
            TerminalEvent::Voided {
                message_id: [7; 32],
                first_nonce: 19,
                count: 1
            }
        )
        .is_err()
    );
}

#[test]
fn genuine_burn_requires_original_payload_owner_nonce_and_emitter() {
    use iroha_sccp::{
        ton_watch::{BurnObservation, Cursor},
        v1::{hashes::payload_hash, payload::SccpTransferPayloadV1},
    };
    let mut owner = vec![0; 4];
    owner.extend_from_slice(&[8; 32]);
    let payload =
        SccpTransferPayloadV1::inbound(SccpNetworkV1::TonMainnet, 19, 1, 55, owner, vec![6; 32])
            .unwrap()
            .encode()
            .unwrap();
    let (event, _, _, _) = genuine(SyntheticTonEventV1::Transfer {
        message_id: [7; 32],
        nonce: 19,
        sender: [8; 32],
        amount: 55,
        payload: payload.clone(),
    });
    let expected = BurnObservation {
        transaction: Cursor {
            lt: 500,
            hash: [1; 32],
        },
        message_index: 0,
        query_id: 1,
        notification_sender: [2; 32],
        message_id: [7; 32],
        nonce: 19,
        owner: [8; 32],
        amount: 55,
        payload_hash: payload_hash(&payload),
    };
    require_ton_burn(&event, [9; 32], &expected).unwrap();
    for variant in 0..4 {
        let mut other = expected;
        match variant {
            0 => other.nonce += 1,
            1 => other.owner[0] ^= 1,
            2 => other.payload_hash[0] ^= 1,
            _ => other.message_id[0] ^= 1,
        }
        assert!(require_ton_burn(&event, [9; 32], &other).is_err());
    }
    assert!(require_ton_burn(&event, [10; 32], &expected).is_err());
}

#[test]
fn rejected_proof_reopens_the_exact_original_pending_envelope() {
    use iroha_data_model::prelude::NetworkId;
    use iroha_sccp_wallet::{
        flow::{SccpFlowActionV1 as Action, SccpFlowV1, drive_step_with_rebroadcast},
        journal::{SccpFlowIdV1, SccpFlowKindV1, SccpJournalRoot},
    };
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("rejected-ton-proof-")
        .tempdir_in(base)
        .unwrap();
    let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::prehashed([7; 32]),
    ));
    let id = SccpFlowIdV1 {
        kind: SccpFlowKindV1::Outbound,
        id: [4; 32],
    };
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network).unwrap().flow(&id).unwrap(),
        *network.as_bytes(),
    )
    .unwrap();
    let step = flow
        .prepare(
            Action::Finalize,
            SccpNetworkV1::TonMainnet,
            vec![9, 8, 7],
            vec![iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
                label: "original.intent".into(),
                bytes: vec![1],
            }],
        )
        .unwrap();
    step.begin_submission().unwrap();
    let original = step.record().clone();
    let (event, _, _, _) = genuine(SyntheticTonEventV1::Finalized {
        message_id: [7; 32],
        nonce: 19,
    });
    assert!(
        drive_step_with_rebroadcast::<eyre::Report>(
            &step,
            true,
            |_| {
                require_ton_terminal(
                    &event,
                    [9; 32],
                    iroha_sccp::ton_watch::TerminalEvent::Finalized {
                        message_id: [8; 32],
                        nonce: 19,
                    },
                )?;
                panic!("a genuine unrelated effect cannot complete the original")
            },
            |_| panic!("a rejected proof cannot dispatch or replace custody")
        )
        .is_err()
    );
    drop(step);
    drop(flow);
    drop(root);
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network).unwrap().flow(&id).unwrap(),
        *network.as_bytes(),
    )
    .unwrap();
    let pending = flow.pending().unwrap().unwrap();
    assert_eq!(pending.record(), &original);
    assert!(pending.outcome().unwrap().is_none());
    assert!(pending.submission_recorded().unwrap());
    assert!(
        flow.prepare(Action::Control, SccpNetworkV1::TonMainnet, vec![1], vec![])
            .is_err()
    );
}

#[test]
fn retained_original_trust_replays_genuine_proof_and_preserves_checkpoint_identity() {
    let (event, proof, _, initial) = genuine(SyntheticTonEventV1::Finalized {
        message_id: [7; 32],
        nonce: 19,
    });
    let now = (1_790_000_000_u64 + 2_000) * 1000;
    let original_cut = norito::json!({"height": 7, "world_root": "selected-original-root"});
    let mut checkpoints = initial.checkpoints.clone();
    checkpoints.extend_from_slice(&initial.checkpoints);
    let item = super::super::retain_source_trust(super::super::SourceTrust {
        network: SccpNetworkV1::TonMainnet,
        original_cut: original_cut.clone(),
        verification_time_ms: now,
        light_client: initial.light_client,
        sets: initial.sets,
        checkpoints,
    })
    .unwrap();
    assert_eq!(item.label, "source.original_trust");
    let mut retained: super::super::SourceTrust = norito::json::from_slice(&item.bytes).unwrap();
    assert_eq!(retained.original_cut, original_cut);
    assert_eq!(retained.verification_time_ms, now);
    assert_eq!(retained.checkpoints, initial.checkpoints);
    let replay = LightClientReplayV1::new(
        SccpChainProfilesV1::genesis(),
        retained.network,
        retained.light_client,
        retained.sets.clone(),
        retained.checkpoints.clone(),
    );
    assert_eq!(
        replay
            .verify_evidence(&proof, retained.verification_time_ms)
            .unwrap()
            .event,
        event
    );
    retained.sets[0].set_bytes[0] ^= 1;
    let forged = LightClientReplayV1::new(
        SccpChainProfilesV1::genesis(),
        retained.network,
        retained.light_client,
        retained.sets.clone(),
        retained.checkpoints.clone(),
    );
    assert!(forged.verify_evidence(&proof, now).is_err());
    retained.sets[0].set_bytes = vec![
        255;
        usize::try_from(iroha_sccp_wallet::journal::MAX_RECORD_BYTES)
            .expect("bounded journal records fit usize")
    ];
    assert!(super::super::retain_source_trust(retained).is_err());
}
