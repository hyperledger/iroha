//! Ethereum light-client scenarios through the public verifier (`specs/sccp.md` §4.13, §11).
//!
//! Every scenario runs at a controlled Taira time against [`SccpLcMemoryStateV1`] world state:
//! the synthetic beacon harness round trip (bootstrap, advances across a period change, inbound
//! and void proofs over EDR-shaped blocks), the update rules (342 participants, finality branch,
//! slot order, fork version, the next-committee period rule), weak subjectivity, the compiled
//! fork bound and its extension without re-initialization, `HeaderChain`, `HistoryContract` and
//! `Backfill` ancestry, equivocation (including a `FinalizedAncestor` record against a forged
//! block between epoch checkpoints), re-initialization through `initialize_light_client` (a
//! frozen client's learned data is discarded, an aged client's checkpoints are kept), stride
//! retention and idempotent advances. Captured mainnet responses (`fixtures/sccp/rpc/eth/`)
//! drive the verifier from a real bootstrap across a real sync-committee period change to a real
//! receipt.
//!
//! `fixtures/sccp/native_transfer_event_v1.json` is generated here; rewrite it after a reviewed
//! layout change with
//! `cargo test -p iroha_sccp --test ethereum_light_client -- --ignored regenerate_native_transfer_event_v1`.

use std::{fs, path::PathBuf};

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        inbound::SccpSourceProofBytesV1,
        light_client::{
            SccpLcBootstrapV1, SccpLcCheckpointOriginV1, SccpLcFreezeReasonV1,
            SccpLcInitExpectationV1, SccpLightClientParamsV1,
        },
        outbound::SccpVoidKindV1,
    },
};
use iroha_sccp::{
    EthereumLightClientError,
    ethereum_source::{EthereumLogV1, EthereumMptRoleV1, mpt_root, verify_mpt_inclusion},
    light_client::{
        self, SccpLcConflictV1, SccpLcError,
        bsc::{BscProofAnchorV1, BscSourceProofV1},
        ethereum::{
            EthereumAncestryV1, EthereumEventSelectorV1, EthereumFinalizedAncestorV1,
            EthereumHeaderSegmentV1, EthereumHistoryProofV1, EthereumLcAdvanceV1, EthereumLcError,
            EthereumLcEvidenceV1, EthereumLogRangeV1, EthereumLogRefV1, EthereumProofAnchorV1,
            EthereumSourceProofV1, EthereumStoredCheckpointRefV1,
        },
        profile::{
            ETHEREUM_MAINNET, SccpLcProfileCatalogV1, SccpLcProfileRefV1,
            SccpLcProfileUnavailableV1,
        },
        proof::{
            SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcEvidenceV1, SccpLcSegmentV1,
            SccpNormalizedEventV1, SccpSourceEmitterV1, SccpSourceProofV1,
        },
        state::{
            SccpLcMemoryStateV1, SccpLcPurgeV1, SccpLcStateView, SccpLcSupersessionV1,
            checkpoint_prune_due, is_permanent_checkpoint,
        },
        ton::{TonMasterchainAnchorV1, TonSourceProofV1},
    },
    test_support::{
        bsc::SyntheticParliaChainV1,
        ethereum::{
            SyntheticBeaconChainV1, SyntheticBlockFieldsV1, SyntheticExecutionHeaderV1,
            SyntheticUpdateSpecV1, advance_bytes, bootstrap_from_beacon_json, execution_header_rlp,
            execution_of, header_chain, header_rlp_from_rpc_json, hex_bytes, history_state,
            mpt_proof_from_rpc_json, receipt_from_rpc_json, receipt_root_and_proof,
            successful_receipt, transfer_log, update_from_beacon_json, voided_log,
        },
        ton::{BitsV1, CellArenaV1, SyntheticTonChainV1, SyntheticTonEventV1},
    },
    v1::{
        constants::{CODEC_EVM_ADDRESS20, CODEC_TAIRA_ACCOUNT},
        destination_abi::{TOPIC_TRANSFER_TO_TAIRA, TOPIC_VOIDED},
        evm_abi::{AbiError, TransferToTairaLogV1},
        hashes::{keccak256, to_hex},
        network::account_codec,
        payload::{PayloadAccountV1, SccpTransferPayloadV1},
    },
};
use norito::json::{Map, Value};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const PERIOD: u64 = 1_868;
const SLOTS_PER_PERIOD: u64 = 8_192;
/// Fixed Taira `NetworkId` bytes of the fixture vectors (the §3.4 example value).
const TAIRA: [u8; 32] = [0x11; 32];
/// Deployment address of the EVM vectors (`word(0x22…22)` is the fixture destination word).
const EMITTER: [u8; 20] = [0x22; 20];
const GENERATOR: &str = "crates/iroha_sccp/tests/ethereum_light_client.rs";

fn slot(offset: u64) -> u64 {
    PERIOD * SLOTS_PER_PERIOD + offset
}

fn params() -> SccpLightClientParamsV1 {
    SccpLightClientParamsV1::defaults_for(ETH).expect("external network")
}

fn taira_recipient() -> Vec<u8> {
    let mut bytes = vec![0x02, 0x01, 0x20];
    bytes.extend_from_slice(&keccak256(&[b"SCCP/FIXTURE/TAIRA/V1", &[1]]));
    bytes
}

/// A light client bootstrapped at `slot(64)` of the synthetic chain.
fn installed(chain: &SyntheticBeaconChainV1, now: u64) -> SccpLcMemoryStateV1 {
    let bootstrap = chain.bootstrap_with_execution(slot(64), &chain.synthetic_execution(slot(64)));
    let initial =
        light_client::verify_bootstrap(ETH, &params(), &bootstrap, now).expect("fresh bootstrap");
    let mut memory = SccpLcMemoryStateV1::new();
    memory.install(ETH, &initial);
    memory
}

fn update_spec(chain: &SyntheticBeaconChainV1, signature_slot: u64) -> SyntheticUpdateSpecV1 {
    SyntheticUpdateSpecV1 {
        attested_slot: signature_slot - 1,
        finalized_slot: signature_slot - 40,
        finalized_execution: chain.synthetic_execution(signature_slot - 40),
        signature_slot,
        include_next_committee: true,
        participants: 512,
        signing_period: None,
        next_committee_period: None,
    }
}

fn advance(chain: &SyntheticBeaconChainV1, specs: &[SyntheticUpdateSpecV1]) -> SccpLcAdvanceV1 {
    SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: specs.iter().map(|spec| chain.update(spec)).collect(),
    })
}

fn inbound_payload(nonce: u64) -> SccpTransferPayloadV1 {
    SccpTransferPayloadV1::inbound(
        ETH,
        nonce,
        1,
        1_000_000_000,
        vec![0x5e; 20],
        taira_recipient(),
    )
    .expect("valid inbound payload")
}

fn transfer_of(payload: &SccpTransferPayloadV1) -> TransferToTairaLogV1 {
    TransferToTairaLogV1 {
        message_id: payload.message_id(&TAIRA).expect("message id"),
        sender: [0x5e; 20],
        nonce: payload.nonce,
        payload: payload.encode().expect("encodes"),
    }
}

/// An EDR-shaped block whose second receipt carries `logs`.
fn block_with_logs(
    number: u64,
    timestamp: u64,
    logs: Vec<EthereumLogV1>,
) -> (
    Vec<u8>,
    iroha_sccp::ethereum_source::EthereumNativeMptProofV1,
) {
    let receipts = vec![successful_receipt(Vec::new()), successful_receipt(logs)];
    let (receipts_root, proof) = receipt_root_and_proof(&receipts, 1);
    let header = execution_header_rlp(&SyntheticBlockFieldsV1 {
        parent_hash: keccak256(&[b"edr-parent", &number.to_be_bytes()]),
        number,
        timestamp,
        state_root: keccak256(&[b"edr-state", &number.to_be_bytes()]),
        receipts_root,
    });
    (header, proof)
}

fn proof_bytes(proof: EthereumSourceProofV1) -> SccpSourceProofBytesV1 {
    SccpSourceProofV1::Ethereum(proof)
        .to_bytes()
        .expect("bounded proof")
}

fn same_block_proof(
    chain: &SyntheticBeaconChainV1,
    header: &[u8],
    receipt_proof: iroha_sccp::ethereum_source::EthereumNativeMptProofV1,
    event: EthereumEventSelectorV1,
    signature_slot: u64,
) -> SccpSourceProofBytesV1 {
    proof_bytes(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
            chain.finality_update_for(execution_of(header), signature_slot),
        )),
        ancestry: EthereumAncestryV1::SameBlock,
        event_header: header.to_vec(),
        transaction_index: 1,
        receipt_proof,
        event,
    })
}

// ---------------------------------------------------------------------------------------------
// Synthetic harness round trip
// ---------------------------------------------------------------------------------------------

#[test]
fn synthetic_harness_roundtrip_through_the_verifier() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(100)) + 5_000;
    // A fresh light client installed through the Parliament path.
    let bootstrap = chain.bootstrap_at_unix_ms(now);
    let initial =
        light_client::verify_bootstrap(ETH, &params(), &bootstrap, now).expect("fresh bootstrap");
    assert_eq!(initial.light_client.head.latest_set_id, PERIOD);
    assert_eq!(
        initial.checkpoints[0].origin,
        SccpLcCheckpointOriginV1::Parliament
    );
    let mut memory = SccpLcMemoryStateV1::new();
    memory.install(ETH, &initial);
    // A burn on an EDR block, finalized by the synthetic committee.
    let payload = inbound_payload(7);
    let (header, receipt_proof) = block_with_logs(
        42,
        now / 1_000,
        vec![transfer_log(EMITTER, &transfer_of(&payload))],
    );
    // The block is finalized by a signature slot that starts at or after its timestamp.
    let signature_slot = chain.signature_slot_for(&execution_of(&header));
    assert_eq!(signature_slot, chain.slot_at_unix_ms(now) + 1);
    let proof = same_block_proof(
        &chain,
        &header,
        receipt_proof,
        EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        signature_slot,
    );
    let verified = light_client::verify_proof(&memory, ETH, &proof, now).expect("valid proof");
    let SccpNormalizedEventV1::TransferToTaira {
        emitter,
        message_id,
        sender,
        nonce,
        payload_hash,
        locator,
    } = &verified.event
    else {
        panic!("a transfer event");
    };
    let deployment = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
        address: EMITTER,
        runtime_code_hash: [0; 32],
    });
    assert!(emitter.matches(&deployment));
    assert_eq!(*message_id, payload.message_id(&TAIRA).expect("id"));
    assert_eq!(*sender, payload.sender);
    assert_eq!(*nonce, payload.nonce);
    assert_eq!(*payload_hash, payload.payload_hash().expect("hash"));
    assert_eq!(locator.source_height, 42);
    assert_eq!(locator.block_hash, execution_of(&header).block_hash);
    assert_eq!(verified.checkpoints.len(), 1);
    memory.record_checkpoints(ETH, &verified.checkpoints);
    let work = light_client::proof_work(ETH, &proof).expect("work");
    assert_eq!(work.proofs, 1);
    assert_eq!(work.ethereum_light_client_updates, 1);
    assert_eq!(work.native_headers, 1);
    assert_eq!(
        work.proof_bytes,
        u64::try_from(proof.len()).expect("length")
    );
}

#[test]
fn advances_cross_a_period_change_and_are_idempotent() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let mut memory = installed(&chain, now);
    let bytes = advance_bytes(&advance(&chain, &[update_spec(&chain, slot(200))]));
    let delta = light_client::apply_advance(&memory, ETH, &bytes, now).expect("valid advance");
    assert!(delta.moves_head());
    assert_eq!(delta.new_sets[0].set_id, PERIOD + 1);
    memory.apply(ETH, &delta);
    let before = memory.light_client(ETH).expect("installed");
    assert_eq!(before.head.latest_set_id, PERIOD + 1);
    assert!(
        light_client::apply_advance(&memory, ETH, &bytes, now + 12_000)
            .expect("re-proof")
            .is_empty(),
        "re-proving stored data succeeds with no change"
    );
    // After the period change, a burn is proven with the committee learned from finality.
    let later_slot = (PERIOD + 1) * SLOTS_PER_PERIOD + 50;
    let later = chain.slot_unix_ms(later_slot);
    let payload = inbound_payload(8);
    let (header, receipt_proof) = block_with_logs(
        43,
        later / 1_000,
        vec![transfer_log(EMITTER, &transfer_of(&payload))],
    );
    let proof = same_block_proof(
        &chain,
        &header,
        receipt_proof,
        EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        later_slot,
    );
    assert!(light_client::verify_proof(&memory, ETH, &proof, later).is_ok());
    // The next advance learns period + 2 from an update signed by period + 1.
    let next = advance_bytes(&chain.catch_up_advance(PERIOD + 1, PERIOD + 2));
    let after = chain.slot_unix_ms((PERIOD + 1) * SLOTS_PER_PERIOD + 300);
    let delta = light_client::apply_advance(&memory, ETH, &next, after).expect("catch-up");
    assert_eq!(delta.new_sets[0].set_id, PERIOD + 2);
    assert_eq!(delta.superseded_sets[0].set_id, PERIOD + 1);
    assert_eq!(
        light_client::advance_work(ETH, &next)
            .expect("work")
            .ethereum_light_client_updates,
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Update rules
// ---------------------------------------------------------------------------------------------

fn advance_error(
    memory: &SccpLcMemoryStateV1,
    update: iroha_sccp::ethereum_source::EthereumNativeLightClientUpdateV1,
    now: u64,
) -> SccpLcError {
    let bytes = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: vec![update],
    }));
    light_client::apply_advance(memory, ETH, &bytes, now).expect_err("the update is rejected")
}

fn consensus(error: EthereumLightClientError) -> SccpLcError {
    SccpLcError::Ethereum(EthereumLcError::Consensus(error))
}

#[test]
fn participation_below_342_is_rejected() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let at_threshold = chain.update(&SyntheticUpdateSpecV1 {
        participants: 342,
        ..update_spec(&chain, slot(200))
    });
    let bytes = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: vec![at_threshold],
    }));
    assert!(light_client::apply_advance(&memory, ETH, &bytes, now).is_ok());
    let below = chain.update(&SyntheticUpdateSpecV1 {
        participants: 341,
        ..update_spec(&chain, slot(200))
    });
    assert_eq!(
        advance_error(&memory, below, now),
        consensus(EthereumLightClientError::InsufficientParticipation(341))
    );
}

#[test]
fn missing_finality_branch_and_slot_ordering_are_rejected() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let mut missing = chain.update(&update_spec(&chain, slot(200)));
    missing.finality_branch = Vec::new();
    assert_eq!(
        advance_error(&memory, missing, now),
        SccpLcError::Ethereum(EthereumLcError::Execution(
            iroha_sccp::ethereum_source::EthereumExecutionError::MalformedWire("finality branch")
        ))
    );
    for (attested, finalized, signature) in [
        (slot(200), slot(160), slot(200)),
        (slot(150), slot(160), slot(200)),
    ] {
        let update = chain.update(&SyntheticUpdateSpecV1 {
            attested_slot: attested,
            finalized_slot: finalized,
            finalized_execution: chain.synthetic_execution(finalized),
            signature_slot: signature,
            ..update_spec(&chain, slot(200))
        });
        assert_eq!(
            advance_error(&memory, update, now),
            consensus(EthereumLightClientError::InvalidSlotOrder)
        );
    }
}

#[test]
fn wrong_fork_version_is_rejected() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let mut forks = ETHEREUM_MAINNET.forks;
    forks[5] = iroha_sccp::ForkActivation::new(forks[5].epoch(), [0x06, 0, 0, 1]);
    let foreign = SyntheticBeaconChainV1::with_profile(
        iroha_sccp::test_support::ethereum::SYNTHETIC_BEACON_SEED_V1,
        iroha_sccp::light_client::profile::EthereumChainProfileV1 {
            forks,
            ..ETHEREUM_MAINNET
        },
    );
    let update = foreign.update(&update_spec(&foreign, slot(200)));
    assert_eq!(
        advance_error(&memory, update, now),
        consensus(EthereumLightClientError::InvalidSyncCommitteeSignature)
    );
}

#[test]
fn next_committee_is_learned_only_when_attested_and_finalized_share_a_period() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let boundary = (PERIOD + 1) * SLOTS_PER_PERIOD;
    let now = chain.slot_unix_ms(boundary + 20);
    let memory = installed(&chain, now);
    let crossing = SyntheticUpdateSpecV1 {
        attested_slot: boundary + 1,
        finalized_slot: boundary - 30,
        finalized_execution: chain.synthetic_execution(boundary - 30),
        signature_slot: boundary + 2,
        signing_period: Some(PERIOD),
        ..update_spec(&chain, slot(200))
    };
    assert_eq!(
        advance_error(&memory, chain.update(&crossing), now),
        consensus(EthereumLightClientError::NextCommitteePeriodMismatch)
    );
    // Without the next committee the same shape is a plain finality update, and it still needs
    // the stored committee of `period(signature_slot)`.
    let finality_only = SyntheticUpdateSpecV1 {
        include_next_committee: false,
        ..crossing
    };
    assert_eq!(
        advance_error(&memory, chain.update(&finality_only), now),
        SccpLcError::UnknownSigningSet { set_id: PERIOD + 1 }
    );
}

// ---------------------------------------------------------------------------------------------
// Weak subjectivity and the fork bound
// ---------------------------------------------------------------------------------------------

#[test]
fn weak_subjectivity_rejects_stale_sets_and_bootstraps() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let stale_from = ETHEREUM_MAINNET.period_end_ms(PERIOD).expect("time") + params().ws_bound_ms;
    let bytes = advance_bytes(&advance(&chain, &[update_spec(&chain, slot(200))]));
    assert!(light_client::apply_advance(&memory, ETH, &bytes, stale_from - 1).is_ok());
    assert_eq!(
        light_client::apply_advance(&memory, ETH, &bytes, stale_from),
        Err(SccpLcError::StaleSigningSet {
            set_id: PERIOD,
            stale_from_ms: stale_from,
        })
    );
    assert_eq!(
        light_client::is_aged(&memory, ETH, stale_from - 1),
        Ok(false)
    );
    assert_eq!(light_client::is_aged(&memory, ETH, stale_from), Ok(true));
    let bootstrap = chain.bootstrap_with_execution(slot(64), &chain.synthetic_execution(slot(64)));
    assert!(matches!(
        light_client::verify_bootstrap(ETH, &params(), &bootstrap, stale_from),
        Err(SccpLcError::StaleSigningSet { .. })
    ));
}

#[test]
fn fork_bound_fails_closed_until_an_extending_version_is_activated() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let mut memory = installed(&chain, now);
    let bytes = advance_bytes(&advance(&chain, &[update_spec(&chain, slot(200))]));
    let bound_epoch = slot(100) / 32;
    // Version 1 ends at `bound_epoch`; a later release appends version 2, which extends it.
    let versions = [
        ETHEREUM_MAINNET.with_supported_until_epoch(bound_epoch),
        ETHEREUM_MAINNET.with_supported_until_epoch(bound_epoch + 1_000),
    ];
    let new_release = SccpLcProfileCatalogV1 {
        ethereum: &versions,
        ..SccpLcProfileCatalogV1::compiled()
    };
    let old_release = SccpLcProfileCatalogV1 {
        ethereum: &versions[..1],
        ..SccpLcProfileCatalogV1::compiled()
    };
    // Before activation both releases run version 1 and commit the same active-profile hash.
    let before = new_release.genesis();
    assert_eq!(old_release.genesis(), before);
    assert_eq!(old_release.genesis().policy_hash(), before.policy_hash());
    let version_1 = new_release.resolve(&before).expect("version 1");
    assert_eq!(old_release.resolve(&before), Ok(version_1));
    assert_eq!(
        light_client::apply_advance_with_profiles(&version_1, &memory, ETH, &bytes, now),
        Err(SccpLcError::ForkBeyondSupported {
            epoch: slot(200) / 32,
            supported_until: bound_epoch,
        })
    );
    // Once the Parliament activates version 2, the same stored light client accepts the same
    // advance: no freeze, no re-initialization.
    let after = before.with(
        ETH,
        SccpLcProfileRefV1 {
            version: 2,
            profile_hash: versions[1].profile_hash(),
        },
    );
    let version_2 = new_release.resolve(&after).expect("version 2");
    let delta = light_client::apply_advance_with_profiles(&version_2, &memory, ETH, &bytes, now)
        .expect("extended profile");
    memory.apply(ETH, &delta);
    assert_eq!(
        memory
            .light_client(ETH)
            .expect("installed")
            .head
            .latest_set_id,
        PERIOD + 1
    );
    assert_ne!(before.policy_hash(), after.policy_hash());
    // A release without version 2 fails closed instead of verifying under version 1.
    assert_eq!(
        old_release.resolve(&after),
        Err(SccpLcProfileUnavailableV1::NotCompiled {
            network: ETH,
            version: 2,
        })
    );
}

// ---------------------------------------------------------------------------------------------
// Ancestry
// ---------------------------------------------------------------------------------------------

fn history_proof(
    chain: &SyntheticBeaconChainV1,
    distance: u64,
    now: u64,
) -> SccpSourceProofBytesV1 {
    let payload = inbound_payload(9);
    let (header, receipt_proof) = block_with_logs(
        5_000,
        now / 1_000 - 3_600,
        vec![transfer_log(EMITTER, &transfer_of(&payload))],
    );
    let block = execution_of(&header);
    let (state_root, history): ([u8; 32], EthereumHistoryProofV1) =
        history_state(&ETHEREUM_MAINNET, block.number, block.block_hash);
    let anchor = SyntheticExecutionHeaderV1 {
        block_hash: keccak256(&[b"anchor", &distance.to_be_bytes()]),
        number: block.number + distance,
        state_root,
        receipts_root: [0x42; 32],
        timestamp: now / 1_000 - 60,
    };
    proof_bytes(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
            chain.finality_update_for(anchor, slot(300)),
        )),
        ancestry: EthereumAncestryV1::HistoryContract(history),
        event_header: header,
        transaction_index: 1,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    })
}

#[test]
fn history_contract_window_edges() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    for distance in [1, 8_191] {
        assert!(
            light_client::verify_proof(&memory, ETH, &history_proof(&chain, distance, now), now)
                .is_ok(),
            "E - B = {distance} is inside the EIP-2935 window"
        );
    }
    for distance in [0, 8_192] {
        assert_eq!(
            light_client::verify_proof(&memory, ETH, &history_proof(&chain, distance, now), now),
            Err(SccpLcError::Ethereum(EthereumLcError::HistoryWindow {
                event_height: 5_000,
                anchor_height: 5_000 + distance,
            })),
            "E - B = {distance} is outside the EIP-2935 window"
        );
    }
}

#[test]
fn header_chain_and_backfill_prove_older_burns() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let payload = inbound_payload(10);
    let (event_header, receipt_proof) = block_with_logs(
        9_000,
        now / 1_000 - 7_200,
        vec![transfer_log(EMITTER, &transfer_of(&payload))],
    );
    let links = header_chain(&event_header, 300);
    // The light client is bootstrapped on the tip; the burn is 300 blocks older.
    let tip = links.last().expect("300 headers");
    let initial = light_client::verify_bootstrap(
        ETH,
        &params(),
        &chain.bootstrap_with_execution(slot(64), &execution_of(tip)),
        now,
    )
    .expect("bootstrap");
    let mut memory = SccpLcMemoryStateV1::new();
    memory.install(ETH, &initial);
    let direct = proof_bytes(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
            source_height: execution_of(tip).number,
        }),
        ancestry: EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
            headers: links.clone(),
        }),
        event_header: event_header.clone(),
        transaction_index: 1,
        receipt_proof: receipt_proof.clone(),
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    });
    assert_eq!(
        light_client::verify_proof(&memory, ETH, &direct, now),
        Err(SccpLcError::TooManyItems {
            kind: "ancestry headers",
            count: 300,
            max: 256,
        })
    );
    // Backfill 100 headers below the tip, then prove from the backfilled checkpoint.
    let backfill = SccpLcAdvanceV1::Backfill {
        segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
            headers: links[199..].to_vec(),
        }),
    }
    .to_bytes()
    .expect("bounded");
    let delta = light_client::apply_advance(&memory, ETH, &backfill, now).expect("backfill");
    assert!(!delta.moves_head());
    assert_eq!(
        delta.checkpoints[0].origin,
        SccpLcCheckpointOriginV1::Backfill
    );
    let backfilled = execution_of(&links[199]);
    assert_eq!(delta.checkpoints[0].data.source_height, backfilled.number);
    memory.apply(ETH, &delta);
    assert_eq!(
        light_client::advance_work(ETH, &backfill)
            .expect("work")
            .native_headers,
        101
    );
    let older = proof_bytes(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
            source_height: backfilled.number,
        }),
        ancestry: EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
            headers: links[..200].to_vec(),
        }),
        event_header,
        transaction_index: 1,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    });
    let verified = light_client::verify_proof(&memory, ETH, &older, now).expect("older burn");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::TransferToTaira { nonce: 10, .. }
    ));
}

#[test]
fn void_proofs_normalize_expired_and_frozen_voids() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let expired_id = keccak256(&[b"voided message"]);
    let (header, receipt_proof) =
        block_with_logs(77, now / 1_000, vec![voided_log(EMITTER, expired_id, 12)]);
    let proof = same_block_proof(
        &chain,
        &header,
        receipt_proof,
        EthereumEventSelectorV1::Void(EthereumLogRangeV1 {
            first_log_index: 0,
            log_count: 1,
        }),
        slot(300),
    );
    let verified = light_client::verify_proof(&memory, ETH, &proof, now).expect("expired void");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::Void {
            kind: SccpVoidKindV1::Expired,
            first_nonce: 12,
            count: 1,
            ..
        }
    ));
    let frozen_logs = (20..24)
        .map(|nonce| voided_log(EMITTER, [0; 32], nonce))
        .collect();
    let (header, receipt_proof) = block_with_logs(78, now / 1_000, frozen_logs);
    let proof = same_block_proof(
        &chain,
        &header,
        receipt_proof,
        EthereumEventSelectorV1::Void(EthereumLogRangeV1 {
            first_log_index: 0,
            log_count: 4,
        }),
        slot(300),
    );
    let verified = light_client::verify_proof(&memory, ETH, &proof, now).expect("frozen void");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::Void {
            kind: SccpVoidKindV1::Frozen,
            first_nonce: 20,
            count: 4,
            message_id_or_zero,
            ..
        } if message_id_or_zero == [0; 32]
    ));
}

// ---------------------------------------------------------------------------------------------
// Equivocation, freezing and retention
// ---------------------------------------------------------------------------------------------

#[test]
fn equivocation_evidence_freezes_the_light_client() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let mut memory = installed(&chain, now);
    let honest = chain.update(&update_spec(&chain, slot(200)));
    let mut forked_execution = chain.synthetic_execution(slot(160));
    forked_execution.block_hash = keccak256(&[b"a conflicting finalized block"]);
    let forked = chain.update(&SyntheticUpdateSpecV1 {
        finalized_execution: forked_execution,
        ..update_spec(&chain, slot(200))
    });
    // The honest update is stored; the conflicting one is refused with a pointer to evidence.
    let honest_advance = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: vec![honest.clone()],
    }));
    let delta = light_client::apply_advance(&memory, ETH, &honest_advance, now).expect("honest");
    memory.apply(ETH, &delta);
    let forked_advance = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: vec![forked.clone()],
    }));
    let refused =
        light_client::apply_advance(&memory, ETH, &forked_advance, now).expect_err("conflict");
    assert_eq!(
        refused,
        SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::Checkpoint {
            source_height: slot(160)
        })
    );
    assert!(
        refused
            .to_string()
            .contains("ReportSccpLightClientEquivocationV1")
    );
    let a = SccpLcEvidenceV1::Ethereum(EthereumLcEvidenceV1::Update(Box::new(honest)))
        .to_bytes()
        .expect("evidence");
    let b = SccpLcEvidenceV1::Ethereum(EthereumLcEvidenceV1::Update(Box::new(forked)))
        .to_bytes()
        .expect("evidence");
    let reason =
        light_client::verify_equivocation(&memory, ETH, &a, &b, now).expect("equivocation");
    assert!(matches!(reason, SccpLcFreezeReasonV1::Equivocation(_)));
    assert_eq!(
        light_client::verify_equivocation(&memory, ETH, &b, &a, now),
        Ok(reason)
    );
    assert_eq!(
        light_client::evidence_work(ETH, &a, &b)
            .expect("work")
            .ethereum_light_client_updates,
        2
    );
    let mut frozen = memory.light_client(ETH).expect("installed");
    frozen.frozen = Some(reason);
    memory.set_light_client(ETH, frozen);
    assert_eq!(
        light_client::apply_advance(&memory, ETH, &honest_advance, now),
        Err(SccpLcError::Frozen(ETH))
    );
}

fn evidence(
    record: EthereumLcEvidenceV1,
) -> iroha_data_model::sccp::light_client::SccpLcEvidenceBytesV1 {
    SccpLcEvidenceV1::Ethereum(record)
        .to_bytes()
        .expect("evidence")
}

#[test]
fn a_forged_block_between_checkpoints_is_reported_through_the_history_contract() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    // The canonical block B and a finalized block E ten blocks later whose EIP-2935 state holds
    // B's hash.
    let (canonical_header, _) = block_with_logs(5_000, now / 1_000 - 3_600, Vec::new());
    let canonical = execution_of(&canonical_header);
    let (state_root, history) =
        history_state(&ETHEREUM_MAINNET, canonical.number, canonical.block_hash);
    let finalized = SyntheticExecutionHeaderV1 {
        block_hash: keccak256(&[b"canonical finalized block"]),
        number: canonical.number + 10,
        state_root,
        receipts_root: [0x42; 32],
        timestamp: canonical.timestamp + 120,
    };
    let honest_update = chain.finality_update_for(finalized, slot(300));
    // A captured quorum finalizes another block at B's height, at a slot that is no epoch
    // boundary; no honest update ever finalizes that slot or height.
    let forged = chain.update(&SyntheticUpdateSpecV1 {
        attested_slot: slot(250),
        finalized_slot: slot(233),
        finalized_execution: SyntheticExecutionHeaderV1 {
            block_hash: keccak256(&[b"forged block at the canonical height"]),
            ..canonical
        },
        signature_slot: slot(251),
        include_next_committee: false,
        ..update_spec(&chain, slot(251))
    });
    let plain = evidence(EthereumLcEvidenceV1::Update(Box::new(
        honest_update.clone(),
    )));
    let forged = evidence(EthereumLcEvidenceV1::Update(Box::new(forged)));
    assert_eq!(
        light_client::verify_equivocation(&memory, ETH, &plain, &forged, now),
        Err(SccpLcError::EvidenceNotConflicting)
    );
    let ancestor = evidence(EthereumLcEvidenceV1::FinalizedAncestor(Box::new(
        EthereumFinalizedAncestorV1 {
            update: honest_update,
            ancestry: EthereumAncestryV1::HistoryContract(history),
            header: canonical_header,
        },
    )));
    let reason = light_client::verify_equivocation(&memory, ETH, &forged, &ancestor, now)
        .expect("the canonical block at the forged height is proven");
    assert!(matches!(reason, SccpLcFreezeReasonV1::Equivocation(_)));
    let work = light_client::evidence_work(ETH, &forged, &ancestor).expect("work");
    assert_eq!(
        (work.ethereum_light_client_updates, work.native_headers),
        (2, 1)
    );
}

#[test]
fn reinitializing_a_frozen_light_client_discards_forged_sets_and_checkpoints() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let mut memory = installed(&chain, now);
    // A captured quorum finalizes a fake burn block and teaches a foreign next committee.
    let payload = inbound_payload(11);
    let (fake_header, receipt_proof) = block_with_logs(
        slot(160),
        chain.slot_unix_ms(slot(160)) / 1_000,
        vec![transfer_log(EMITTER, &transfer_of(&payload))],
    );
    let forged = chain.update(&SyntheticUpdateSpecV1 {
        finalized_execution: execution_of(&fake_header),
        next_committee_period: Some(PERIOD + 9),
        ..update_spec(&chain, slot(200))
    });
    let forged_advance = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: vec![forged.clone()],
    }));
    let delta =
        light_client::apply_advance(&memory, ETH, &forged_advance, now).expect("quorum-signed");
    memory.apply(ETH, &delta);
    let fake_burn = proof_bytes(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
            source_height: slot(160),
        }),
        ancestry: EthereumAncestryV1::SameBlock,
        event_header: fake_header,
        transaction_index: 1,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    });
    assert!(light_client::verify_proof(&memory, ETH, &fake_burn, now).is_ok());
    // The honest update conflicts with the stored forgery, and the pair freezes the client.
    let honest = chain.update(&update_spec(&chain, slot(200)));
    let honest_advance = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
        updates: vec![honest.clone()],
    }));
    assert!(matches!(
        light_client::apply_advance(&memory, ETH, &honest_advance, now),
        Err(SccpLcError::ConflictsWithStoredData(_))
    ));
    let reason = light_client::verify_equivocation(
        &memory,
        ETH,
        &evidence(EthereumLcEvidenceV1::Update(Box::new(forged))),
        &evidence(EthereumLcEvidenceV1::Update(Box::new(honest))),
        now,
    )
    .expect("equivocation");
    let mut frozen = memory.light_client(ETH).expect("installed");
    frozen.frozen = Some(reason);
    memory.set_light_client(ETH, frozen);
    // The Parliament re-initializes it with a fresh bootstrap.
    let reinit_at = chain.slot_unix_ms(slot(320));
    let bootstrap =
        chain.bootstrap_with_execution(slot(310), &chain.synthetic_execution(slot(310)));
    assert_eq!(
        light_client::initialize_light_client(
            &memory,
            ETH,
            SccpLcInitExpectationV1::Absent,
            &params(),
            &bootstrap,
            reinit_at
        ),
        Err(SccpLcError::UnexpectedLightClientState {
            network: ETH,
            expected: SccpLcInitExpectationV1::Absent,
        })
    );
    let initial = light_client::initialize_light_client(
        &memory,
        ETH,
        SccpLcInitExpectationV1::Unusable,
        &params(),
        &bootstrap,
        reinit_at,
    )
    .expect("a frozen light client is re-initialized");
    assert_eq!(initial.purge, SccpLcPurgeV1::DiscardUnvetted);
    assert!(initial.superseded_sets.is_empty());
    memory.install(ETH, &initial);
    // Neither the forged checkpoint nor the forged committee survives.
    assert_eq!(
        light_client::verify_proof(&memory, ETH, &fake_burn, reinit_at),
        Err(SccpLcError::UnknownCheckpoint {
            source_height: slot(160)
        })
    );
    assert!(memory.consensus_set(ETH, PERIOD + 1).is_none());
    assert_eq!(memory.set_count(ETH), 1);
    // Parliament checkpoints stay: the first bootstrap's and the new one.
    assert_eq!(
        memory.checkpoint(ETH, slot(64)).map(|stored| stored.origin),
        Some(SccpLcCheckpointOriginV1::Parliament)
    );
    assert!(memory.checkpoint(ETH, slot(310)).is_some());
    // The honest data is learned again.
    let after = chain.slot_unix_ms(slot(400));
    let delta = light_client::apply_advance(&memory, ETH, &honest_advance, after)
        .expect("the honest committee and checkpoint are accepted");
    assert_eq!(delta.new_sets[0].set_id, PERIOD + 1);
    assert_eq!(delta.checkpoints[0].data.source_height, slot(160));
}

#[test]
fn reinitializing_an_aged_light_client_keeps_its_checkpoints() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let mut memory = installed(&chain, now);
    let checkpoint_only = advance_bytes(&advance(
        &chain,
        &[SyntheticUpdateSpecV1 {
            include_next_committee: false,
            ..update_spec(&chain, slot(200))
        }],
    ));
    let delta = light_client::apply_advance(&memory, ETH, &checkpoint_only, now).expect("advance");
    memory.apply(ETH, &delta);
    let initialize = |memory: &SccpLcMemoryStateV1, bootstrap: &SccpLcBootstrapV1, at: u64| {
        light_client::initialize_light_client(
            memory,
            ETH,
            SccpLcInitExpectationV1::Unusable,
            &params(),
            bootstrap,
            at,
        )
    };
    // A healthy light client is never replaced.
    assert_eq!(
        initialize(&memory, &chain.bootstrap_at_unix_ms(now), now),
        Err(SccpLcError::UnexpectedLightClientState {
            network: ETH,
            expected: SccpLcInitExpectationV1::Unusable,
        })
    );
    // Aged beyond its bound, it is re-initialized without a purge.
    let deadline = light_client::weak_subjectivity_deadline_ms(&memory, ETH).expect("deadline");
    assert_eq!(light_client::is_aged(&memory, ETH, deadline), Ok(true));
    let bootstrap = chain.bootstrap_at_unix_ms(deadline);
    let bootstrap_height = chain.slot_at_unix_ms(deadline);
    // A kept record at the bootstrap height that describes another block blocks the action.
    let mut conflicting = memory.checkpoint(ETH, slot(160)).expect("recorded");
    conflicting.data.source_height = bootstrap_height;
    memory.record_checkpoints(ETH, &[conflicting]);
    assert_eq!(
        initialize(&memory, &bootstrap, deadline),
        Err(SccpLcError::ConflictsWithStoredData(
            SccpLcConflictV1::Checkpoint {
                source_height: bootstrap_height
            }
        ))
    );
    memory.remove_checkpoint(ETH, bootstrap_height);
    let initial = initialize(&memory, &bootstrap, deadline).expect("aged");
    assert_eq!(initial.purge, SccpLcPurgeV1::KeepStored);
    let superseded_at = ETHEREUM_MAINNET.period_start_ms(PERIOD + 1).expect("time");
    assert_eq!(
        initial.superseded_sets,
        vec![SccpLcSupersessionV1 {
            set_id: PERIOD,
            superseded_at_source_ms: superseded_at,
        }]
    );
    memory.install(ETH, &initial);
    assert!(initial.light_client.head.latest_set_id > PERIOD);
    assert_eq!(
        memory
            .consensus_set(ETH, PERIOD)
            .and_then(|set| set.superseded_at_source_ms),
        Some(superseded_at)
    );
    assert_eq!(
        memory
            .checkpoint(ETH, slot(160))
            .map(|stored| stored.origin),
        Some(SccpLcCheckpointOriginV1::Advance),
        "checkpoints of an aged light client keep old burns provable"
    );
}

#[test]
fn initialize_light_client_requires_the_expected_state() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let bootstrap = chain.bootstrap_at_unix_ms(now);
    let empty = SccpLcMemoryStateV1::new();
    assert_eq!(
        light_client::initialize_light_client(
            &empty,
            ETH,
            SccpLcInitExpectationV1::Unusable,
            &params(),
            &bootstrap,
            now
        ),
        Err(SccpLcError::UnexpectedLightClientState {
            network: ETH,
            expected: SccpLcInitExpectationV1::Unusable,
        })
    );
    let initial = light_client::initialize_light_client(
        &empty,
        ETH,
        SccpLcInitExpectationV1::Absent,
        &params(),
        &bootstrap,
        now,
    )
    .expect("first installation");
    assert_eq!(initial.purge, SccpLcPurgeV1::DiscardUnvetted);
    assert_eq!(
        Ok(initial),
        light_client::verify_bootstrap(ETH, &params(), &bootstrap, now)
    );
    assert_eq!(
        light_client::initialize_light_client(
            &empty,
            SccpNetworkV1::SoraTaira,
            SccpLcInitExpectationV1::Absent,
            &params(),
            &bootstrap,
            now
        ),
        Err(SccpLcError::UnsupportedNetwork(SccpNetworkV1::SoraTaira))
    );
}

#[test]
fn checkpoints_follow_stride_retention() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(700));
    let mut memory = installed(&chain, now);
    let bytes = advance_bytes(&advance(
        &chain,
        &[
            update_spec(&chain, slot(200)),
            update_spec(&chain, slot(400)),
            update_spec(&chain, slot(600)),
        ],
    ));
    let delta = light_client::apply_advance(&memory, ETH, &bytes, now).expect("advance");
    memory.apply(ETH, &delta);
    let params = params();
    let heights = [slot(64), slot(160), slot(360), slot(560)];
    // Every height lies in stride bucket `PERIOD` (8 192 blocks per bucket).
    let lowest = heights.iter().copied().min();
    let prune_at = now + params.checkpoint_prune_after_ms;
    for height in heights {
        let checkpoint = memory.checkpoint(ETH, height).expect("recorded");
        let permanent = is_permanent_checkpoint(ETH, &checkpoint, params.checkpoint_stride, lowest);
        // The lowest is the Parliament-installed bootstrap checkpoint.
        assert_eq!(permanent, height == slot(64), "height {height}");
        assert_eq!(
            checkpoint_prune_due(ETH, &checkpoint, &params, lowest, prune_at),
            !permanent
        );
    }
    let advance_checkpoint = memory.checkpoint(ETH, slot(160)).expect("recorded");
    assert!(is_permanent_checkpoint(
        ETH,
        &advance_checkpoint,
        params.checkpoint_stride,
        Some(slot(160))
    ));
}

// ---------------------------------------------------------------------------------------------
// Captured mainnet data
// ---------------------------------------------------------------------------------------------

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp")
}

fn rpc_json(name: &str) -> Value {
    let path = fixture_dir().join("rpc/eth").join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    norito::json::from_str(&text).expect("captured JSON parses")
}

fn result(value: &Value) -> &Value {
    value.get("result").expect("JSON-RPC result")
}

struct Mainnet {
    finality: iroha_sccp::ethereum_source::EthereumNativeLightClientUpdateV1,
    now: u64,
    memory: SccpLcMemoryStateV1,
}

/// Bootstrap in period 1867, then advance across the 1867 → 1868 → 1869 period changes.
fn mainnet_light_client() -> Mainnet {
    let schedule = ETHEREUM_MAINNET.schedule().expect("mainnet");
    let finality = update_from_beacon_json(&rpc_json("finality_update.json"), &schedule);
    let now = ETHEREUM_MAINNET
        .slot_start_ms(finality.signature_slot)
        .expect("time")
        + 60_000;
    let bootstrap =
        SccpLcBootstrapDataV1::Ethereum(bootstrap_from_beacon_json(&rpc_json("bootstrap.json")))
            .to_bootstrap()
            .expect("bootstrap frame");
    let initial = light_client::verify_bootstrap(ETH, &params(), &bootstrap, now)
        .expect("captured bootstrap verifies");
    assert_eq!(initial.light_client.head.latest_set_id, 1_867);
    let mut memory = SccpLcMemoryStateV1::new();
    memory.install(ETH, &initial);
    let updates = rpc_json("updates.json")
        .as_array()
        .expect("update list")
        .iter()
        .map(|update| update_from_beacon_json(update, &schedule))
        .collect::<Vec<_>>();
    assert_eq!(updates.len(), 2);
    let bytes = advance_bytes(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 { updates }));
    let delta =
        light_client::apply_advance(&memory, ETH, &bytes, now).expect("captured updates verify");
    let learned: Vec<u64> = delta.new_sets.iter().map(|set| set.set_id).collect();
    assert_eq!(learned, vec![1_868, 1_869]);
    memory.apply(ETH, &delta);
    Mainnet {
        finality,
        now,
        memory,
    }
}

const EVENT_BLOCK: u64 = 26_069_527;
const FINALIZED_BLOCK: u64 = 26_069_545;

fn block_header(number: u64) -> Vec<u8> {
    let block = rpc_json(&format!("block_{number}.json"));
    let header = header_rlp_from_rpc_json(result(&block));
    let hash = hex_bytes(
        result(&block)
            .get("hash")
            .and_then(Value::as_str)
            .expect("hash"),
    );
    assert_eq!(
        keccak256(&[&header]).to_vec(),
        hash,
        "block {number} re-encodes"
    );
    header
}

/// The captured receipts of the event block and the proof of the first receipt with a
/// three-topic log.
fn mainnet_receipt() -> (
    u32,
    u32,
    iroha_sccp::ethereum_source::EthereumNativeMptProofV1,
) {
    let receipts = rpc_json(&format!("receipts_{EVENT_BLOCK}.json"));
    let entries: Vec<(Vec<u8>, Vec<u8>)> = result(&receipts)
        .as_array()
        .expect("receipts")
        .iter()
        .zip(0_u64..)
        .map(|(receipt, index)| {
            (
                iroha_sccp::ethereum_source::rlp_encode_u64(index),
                receipt_from_rpc_json(receipt),
            )
        })
        .collect();
    let header = iroha_sccp::ethereum_source::decode_execution_header(&block_header(EVENT_BLOCK))
        .expect("header");
    assert_eq!(mpt_root(&entries), Some(header.receipts_root));
    let (index, log_index) = result(&receipts)
        .as_array()
        .expect("receipts")
        .iter()
        .enumerate()
        .find_map(|(index, receipt)| {
            receipt
                .get("logs")
                .and_then(Value::as_array)
                .and_then(|logs| {
                    logs.iter().position(|log| {
                        log.get("topics")
                            .and_then(Value::as_array)
                            .is_some_and(|topics| topics.len() == 3)
                    })
                })
                .map(|log_index| (index, log_index))
        })
        .expect("a receipt with a three-topic log");
    let proof =
        iroha_sccp::ethereum_source::mpt_proof(&entries, &entries[index].0).expect("receipt proof");
    let opened = verify_mpt_inclusion(
        header.receipts_root,
        &entries[index].0,
        &proof,
        EthereumMptRoleV1::Receipt,
    )
    .expect("receipt opens");
    assert_eq!(opened, entries[index].1);
    (
        u32::try_from(index).expect("index"),
        u32::try_from(log_index).expect("log index"),
        proof,
    )
}

fn mainnet_proof(mainnet: &Mainnet, ancestry: EthereumAncestryV1) -> SccpSourceProofBytesV1 {
    let (transaction_index, log_index, receipt_proof) = mainnet_receipt();
    proof_bytes(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(mainnet.finality.clone())),
        ancestry,
        event_header: block_header(EVENT_BLOCK),
        transaction_index,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index }),
    })
}

#[test]
fn mainnet_bootstrap_advances_across_a_period_change() {
    let mainnet = mainnet_light_client();
    let head = mainnet.memory.light_client(ETH).expect("installed").head;
    assert_eq!(head.latest_set_id, 1_869);
    assert_eq!(
        mainnet
            .memory
            .consensus_set(ETH, 1_867)
            .and_then(|set| set.superseded_at_source_ms),
        ETHEREUM_MAINNET.period_start_ms(1_868)
    );
    // A mainnet period is not an SCCP stride bucket: the head is an execution block number.
    assert!(head.latest_finalized.source_height > 26_000_000);
}

#[test]
fn mainnet_finality_ancestry_and_receipt_reach_the_event_check() {
    let mainnet = mainnet_light_client();
    // Mainnet has no SCCP deployment, so a verified proof stops exactly at the event decoding:
    // finality, ancestry and receipt inclusion all passed.
    let not_sccp = Err(SccpLcError::Ethereum(EthereumLcError::Event(
        AbiError::WrongTopic,
    )));
    let chain: Vec<Vec<u8>> = (EVENT_BLOCK + 1..=FINALIZED_BLOCK)
        .map(block_header)
        .collect();
    let header_chain_proof = mainnet_proof(
        &mainnet,
        EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 { headers: chain }),
    );
    assert_eq!(
        light_client::verify_proof(&mainnet.memory, ETH, &header_chain_proof, mainnet.now),
        not_sccp
    );
    let history = rpc_json("history_proof.json");
    let history = result(&history);
    let storage = history
        .get("storageProof")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .expect("one storage proof");
    let history_contract_proof = mainnet_proof(
        &mainnet,
        EthereumAncestryV1::HistoryContract(EthereumHistoryProofV1 {
            account_proof: mpt_proof_from_rpc_json(history, "accountProof"),
            storage_proof: mpt_proof_from_rpc_json(storage, "proof"),
        }),
    );
    assert_eq!(
        light_client::verify_proof(&mainnet.memory, ETH, &history_contract_proof, mainnet.now),
        not_sccp
    );
    let same_block = mainnet_proof(&mainnet, EthereumAncestryV1::SameBlock);
    assert_eq!(
        light_client::verify_proof(&mainnet.memory, ETH, &same_block, mainnet.now),
        Err(SccpLcError::Ethereum(
            EthereumLcError::AncestryAnchorMismatch
        ))
    );
    // One hour later than the controlled time the proof is unchanged; far later the committee
    // of the signature period is stale.
    assert_eq!(
        light_client::verify_proof(
            &mainnet.memory,
            ETH,
            &header_chain_proof,
            mainnet.now + 3_600_000
        ),
        not_sccp
    );
    let stale = ETHEREUM_MAINNET.period_end_ms(1_868).expect("time") + params().ws_bound_ms;
    assert!(matches!(
        light_client::verify_proof(&mainnet.memory, ETH, &header_chain_proof, stale),
        Err(SccpLcError::StaleSigningSet { set_id: 1_868, .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// fixtures/sccp/native_transfer_event_v1.json
// ---------------------------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> Value {
    Value::String(format!("0x{}", to_hex(bytes)))
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn num(value: u64) -> Value {
    assert!(value < (1 << 53), "JSON numbers stay exact in JavaScript");
    Value::from(value)
}

fn obj(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        assert!(
            map.insert(key.to_owned(), value).is_none(),
            "duplicate {key}"
        );
    }
    Value::Object(map)
}

fn account(account: &PayloadAccountV1) -> Value {
    obj(vec![
        ("codec", num(u64::from(account.codec))),
        ("bytes", hex(&account.bytes)),
    ])
}

fn external_sender(network: SccpNetworkV1) -> Vec<u8> {
    let domain = u8::try_from(network.domain_id()).expect("SCCP domains fit in a byte");
    let body = keccak256(&[b"SCCP/FIXTURE/EXTERNAL/V1", &[domain]]);
    match network {
        SccpNetworkV1::TonMainnet => {
            let mut bytes = vec![0; 4];
            bytes.extend_from_slice(&body);
            bytes
        }
        _ => body[12..].to_vec(),
    }
}

fn log_value(log: &EthereumLogV1) -> Value {
    obj(vec![
        ("address", hex(&log.address)),
        (
            "topics",
            Value::Array(log.topics.iter().map(|topic| hex(topic)).collect()),
        ),
        ("data", hex(&log.data)),
    ])
}

fn transfer_normalized(emitter: &[u8], payload: &SccpTransferPayloadV1) -> Value {
    obj(vec![
        ("kind", text("transfer_to_taira")),
        ("emitter", hex(emitter)),
        ("message_id", hex(&payload.message_id(&TAIRA).expect("id"))),
        ("sender", account(&payload.sender)),
        ("nonce", num(payload.nonce)),
        ("payload_hash", hex(&payload.payload_hash().expect("hash"))),
    ])
}

fn void_normalized(kind: &str, first_nonce: u64, count: u64, message_id: &[u8; 32]) -> Value {
    obj(vec![
        ("kind", text("void")),
        ("emitter", hex(&EMITTER)),
        ("void_kind", text(kind)),
        ("first_nonce", num(first_nonce)),
        ("count", num(count)),
        ("message_id_or_zero", hex(message_id)),
    ])
}

fn transfer_vector(network: SccpNetworkV1) -> Value {
    let sender = external_sender(network);
    let payload = SccpTransferPayloadV1::inbound(
        network,
        7,
        1,
        1_000_000_000,
        sender.clone(),
        taira_recipient(),
    )
    .expect("valid inbound payload");
    let encoded = payload.encode().expect("encodes");
    let mut entries = vec![
        ("source_profile", text(network.profile_key())),
        ("route_revision", num(1)),
        ("nonce", num(7)),
        ("amount", text("1000000000")),
        ("sender", account(&payload.sender)),
        (
            "recipient",
            account(&PayloadAccountV1::new(
                CODEC_TAIRA_ACCOUNT,
                taira_recipient(),
            )),
        ),
        ("payload", hex(&encoded)),
        ("payload_hash", hex(&payload.payload_hash().expect("hash"))),
        ("message_id", hex(&payload.message_id(&TAIRA).expect("id"))),
    ];
    match network {
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => {
            assert_eq!(account_codec(network), CODEC_EVM_ADDRESS20);
            let log = transfer_log(
                EMITTER,
                &TransferToTairaLogV1 {
                    message_id: payload.message_id(&TAIRA).expect("id"),
                    sender: sender.as_slice().try_into().expect("20 bytes"),
                    nonce: 7,
                    payload: encoded,
                },
            );
            entries.push(("log", log_value(&log)));
            entries.push(("normalized", transfer_normalized(&EMITTER, &payload)));
        }
        SccpNetworkV1::TonMainnet => {
            let owner: [u8; 32] = sender[4..].try_into().expect("36-byte TON account");
            let body = ton_transfer_body(
                &payload.message_id(&TAIRA).expect("id"),
                7,
                &owner,
                1_000_000_000,
                &encoded,
            );
            entries.push(("minter", hex(&TON_MINTER)));
            entries.push(("ext_out_body", hex(&body)));
            entries.push(("normalized", transfer_normalized(&TON_MINTER, &payload)));
        }
        SccpNetworkV1::SoraTaira => unreachable!("Taira is no inbound source"),
    }
    obj(entries)
}

/// Minter account of the TON vector.
const TON_MINTER: [u8; 32] = [0x44; 32];

/// The canonical `BoC` of a `sccp_transfer_to_taira` external-out body (§5.3.3): op, message id,
/// nonce, `addr_std` of the burning owner, `Coins` amount, and the payload as `^SnakeBytes`
/// (127-byte chunks, each referencing the next).
fn ton_transfer_body(
    message_id: &[u8; 32],
    nonce: u64,
    owner: &[u8; 32],
    amount: u128,
    payload: &[u8],
) -> Vec<u8> {
    let mut arena = CellArenaV1::new();
    let mut next: Option<usize> = None;
    for chunk in payload.chunks(127).rev() {
        let mut bits = BitsV1::new();
        bits.bytes(chunk);
        let refs: Vec<usize> = next.into_iter().collect();
        next = Some(arena.cell(&bits, &refs));
    }
    let mut body = BitsV1::new();
    body.uint(0x5343_5454, 32)
        .bytes(message_id)
        .uint(u128::from(nonce), 64)
        .std_address(0, owner)
        .coins(amount);
    let root = arena.cell(&body, &[next.expect("a nonempty payload")]);
    arena.boc(root)
}

fn native_transfer_event_fixture() -> Value {
    let expired_id = keccak256(&[b"SCCP/FIXTURE/VOIDED/V1"]);
    let expired_log = voided_log(EMITTER, expired_id, 9);
    let frozen_logs: Vec<EthereumLogV1> = (10..13)
        .map(|nonce| voided_log(EMITTER, [0; 32], nonce))
        .collect();
    obj(vec![
        ("schema", text("iroha_sccp/native_transfer_event_v1")),
        (
            "spec",
            text("specs/sccp.md revision 5, §3.2, §3.3, §4.12.1, §4.12.2, §4.16, §5.1.8"),
        ),
        ("generator", text(GENERATOR)),
        ("taira_network_id", hex(&TAIRA)),
        (
            "event_topics",
            obj(vec![
                ("SccpTransferToTaira", hex(&TOPIC_TRANSFER_TO_TAIRA)),
                ("SccpVoided", hex(&TOPIC_VOIDED)),
            ]),
        ),
        (
            "transfers",
            Value::Array(
                [
                    SccpNetworkV1::EthereumMainnet,
                    SccpNetworkV1::BscMainnet,
                    SccpNetworkV1::TonMainnet,
                ]
                .into_iter()
                .map(transfer_vector)
                .collect(),
            ),
        ),
        (
            "voids",
            Value::Array(vec![
                obj(vec![
                    ("name", text("evm_void_expired")),
                    ("logs", Value::Array(vec![log_value(&expired_log)])),
                    ("normalized", void_normalized("expired", 9, 1, &expired_id)),
                ]),
                obj(vec![
                    ("name", text("evm_void_frozen")),
                    (
                        "logs",
                        Value::Array(frozen_logs.iter().map(log_value).collect()),
                    ),
                    ("normalized", void_normalized("frozen", 10, 3, &[0; 32])),
                ]),
            ]),
        ),
    ])
}

fn render(value: &Value) -> String {
    let mut out = norito::json::to_string_pretty(value).expect("render fixture");
    out.push('\n');
    out
}

fn native_fixture_path() -> PathBuf {
    fixture_dir().join("native_transfer_event_v1.json")
}

/// The Ethereum verifier yields exactly the normalized events the fixture records.
fn verifier_normalized(logs: Vec<EthereumLogV1>, selector: EthereumEventSelectorV1) -> Value {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let (header, receipt_proof) = block_with_logs(100, now / 1_000, logs);
    let proof = same_block_proof(&chain, &header, receipt_proof, selector, slot(300));
    match light_client::verify_proof(&memory, ETH, &proof, now)
        .expect("fixture vectors verify")
        .event
    {
        SccpNormalizedEventV1::TransferToTaira {
            emitter: SccpSourceEmitterV1::Evm(emitter),
            message_id,
            sender,
            nonce,
            payload_hash,
            ..
        } => obj(vec![
            ("kind", text("transfer_to_taira")),
            ("emitter", hex(&emitter)),
            ("message_id", hex(&message_id)),
            ("sender", account(&sender)),
            ("nonce", num(nonce)),
            ("payload_hash", hex(&payload_hash)),
        ]),
        SccpNormalizedEventV1::Void {
            emitter: SccpSourceEmitterV1::Evm(emitter),
            kind,
            first_nonce,
            count,
            message_id_or_zero,
            ..
        } => {
            assert_eq!(emitter, EMITTER);
            let kind = match kind {
                SccpVoidKindV1::Expired => "expired",
                SccpVoidKindV1::Frozen => "frozen",
            };
            void_normalized(kind, first_nonce, count, &message_id_or_zero)
        }
        other => panic!("unexpected event {other:?}"),
    }
}

fn field_bytes(vector: &Value, field: &str) -> Vec<u8> {
    hex_bytes(
        vector
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing {field}")),
    )
}

/// The normalized event JSON of a verified transfer to Taira.
fn transfer_event_json(emitter: &[u8], event: &SccpNormalizedEventV1) -> Value {
    let SccpNormalizedEventV1::TransferToTaira {
        message_id,
        sender,
        nonce,
        payload_hash,
        ..
    } = event
    else {
        panic!("transfer expected, got {event:?}");
    };
    obj(vec![
        ("kind", text("transfer_to_taira")),
        ("emitter", hex(emitter)),
        ("message_id", hex(message_id)),
        ("sender", account(sender)),
        ("nonce", num(*nonce)),
        ("payload_hash", hex(payload_hash)),
    ])
}

/// The TON verifier's normalized event of the TON transfer vector, emitted by a synthetic
/// minter whose external-out body must equal the vector's `ext_out_body`.
fn ton_verifier_normalized(vector: &Value) -> Value {
    let ton = SccpNetworkV1::TonMainnet;
    let sender = vector.get("sender").expect("sender");
    let owner: [u8; 32] = field_bytes(sender, "bytes")[4..]
        .try_into()
        .expect("36-byte TON account");
    let event = SyntheticTonEventV1::Transfer {
        message_id: field_bytes(vector, "message_id")
            .try_into()
            .expect("32 bytes"),
        nonce: vector.get("nonce").and_then(Value::as_u64).expect("nonce"),
        sender: owner,
        amount: vector
            .get("amount")
            .and_then(Value::as_str)
            .and_then(|amount| amount.parse().ok())
            .expect("amount"),
        payload: field_bytes(vector, "payload"),
    };
    assert_eq!(
        SyntheticTonChainV1::event_body_boc(&event),
        field_bytes(vector, "ext_out_body"),
        "the synthetic minter emits the fixture body"
    );
    let minter: [u8; 32] = field_bytes(vector, "minter").try_into().expect("32 bytes");
    let t0: u32 = 1_790_000_000;
    let chain = SyntheticTonChainV1::new([0x54; 32]);
    let mut memory = SccpLcMemoryStateV1::new();
    let initial = light_client::initialize_light_client(
        &memory,
        ton,
        SccpLcInitExpectationV1::Absent,
        &SccpLightClientParamsV1::defaults_for(ton).expect("external"),
        &chain.bootstrap(100, 0, t0, t0 + 65_536),
        u64::from(t0) * 1_000 + 60_000,
    )
    .expect("bootstrap");
    memory.install(ton, &initial);
    let genesis = chain.genesis_shard();
    let event_block = chain.shard_block(10, &genesis, &genesis, &minter, Some(&(500, event, true)));
    let (anchor, _) = chain.master_block(150, 100, 0, t0 + 500, &event_block.link.block_id, &[], 4);
    let proof = SccpSourceProofV1::Ton(TonSourceProofV1 {
        masterchain: TonMasterchainAnchorV1::Signed(anchor),
        shard_blocks: vec![event_block.link.clone()],
        event_block_proof: event_block.link.header_proof,
        transaction: event_block.transaction.expect("transaction"),
        transaction_lt: 500,
        message_index: 0,
        minter,
    })
    .to_bytes()
    .expect("bounded");
    let event = light_client::verify_proof(&memory, ton, &proof, u64::from(t0 + 2_000) * 1_000)
        .expect("the TON vector verifies")
        .event;
    assert_eq!(event.emitter(), &SccpSourceEmitterV1::Ton(minter));
    transfer_event_json(&minter, &event)
}

/// Prove the BSC fixture receipt under a genuine synthetic Parlia finality proof.
fn bsc_verifier_normalized(vector: &Value) -> Value {
    let network = SccpNetworkV1::BscMainnet;
    let receipts = vec![successful_receipt(logs_of(vector))];
    let (root, receipt_proof) = receipt_root_and_proof(&receipts, 0);
    let chain = SyntheticParliaChainV1::new([0x42; 32], 21, 16).with_receipts_root(5_390, root);
    let params = SccpLightClientParamsV1::defaults_for(network).expect("BSC parameters");
    let initial = light_client::verify_bootstrap(
        network,
        &params,
        &chain.bootstrap(5),
        SyntheticParliaChainV1::time_ms(5_000) + 1_000,
    )
    .expect("BSC bootstrap verifies");
    let mut memory = SccpLcMemoryStateV1::new();
    memory.install(network, &initial);
    let step = chain.step(5_390, 5_400, 5_000, None);
    let proof = SccpSourceProofV1::Bsc(BscSourceProofV1 {
        anchor: BscProofAnchorV1::Finality(step.finality),
        headers: step.headers,
        transaction_index: 0,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    })
    .to_bytes()
    .expect("bounded BSC proof");
    let verified = light_client::verify_proof(
        &memory,
        network,
        &proof,
        SyntheticParliaChainV1::time_ms(5_400) + 2_000,
    )
    .expect("BSC fixture verifies");
    let SccpNormalizedEventV1::TransferToTaira {
        emitter: SccpSourceEmitterV1::Evm(emitter),
        message_id,
        sender,
        nonce,
        payload_hash,
        locator,
        ..
    } = verified.event
    else {
        panic!("BSC transfer expected")
    };
    assert_eq!(locator.source_height, 5_390);
    assert_eq!(locator.block_hash, chain.header(5_390).hash);
    obj(vec![
        ("kind", text("transfer_to_taira")),
        ("emitter", hex(&emitter)),
        ("message_id", hex(&message_id)),
        ("sender", account(&sender)),
        ("nonce", num(nonce)),
        ("payload_hash", hex(&payload_hash)),
    ])
}

fn logs_of(vector: &Value) -> Vec<EthereumLogV1> {
    let logs = vector
        .get("logs")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| vector.get("log").map(|log| vec![log.clone()]))
        .expect("logs");
    logs.iter()
        .map(|log| EthereumLogV1 {
            address: hex_bytes(log.get("address").and_then(Value::as_str).expect("address"))
                .try_into()
                .expect("20 bytes"),
            topics: log
                .get("topics")
                .and_then(Value::as_array)
                .expect("topics")
                .iter()
                .map(|topic| {
                    hex_bytes(topic.as_str().expect("topic"))
                        .try_into()
                        .expect("32 bytes")
                })
                .collect(),
            data: hex_bytes(log.get("data").and_then(Value::as_str).expect("data")),
        })
        .collect()
}

#[test]
fn native_transfer_event_fixture_matches_the_verifier() {
    let generated = native_transfer_event_fixture();
    let path = native_fixture_path();
    let actual = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        actual == render(&generated),
        "{} is stale; regenerate it with \
         `cargo test -p iroha_sccp --test ethereum_light_client -- --ignored regenerate_native_transfer_event_v1`",
        path.display()
    );
    let transfers = generated
        .get("transfers")
        .and_then(Value::as_array)
        .expect("transfers");
    let eth = &transfers[0];
    assert_eq!(
        verifier_normalized(
            logs_of(eth),
            EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 })
        ),
        eth.get("normalized").cloned().expect("normalized")
    );
    assert_eq!(
        bsc_verifier_normalized(&transfers[1]),
        transfers[1].get("normalized").cloned().expect("normalized")
    );
    let voids = generated
        .get("voids")
        .and_then(Value::as_array)
        .expect("voids");
    for (vector, count) in [(&voids[0], 1), (&voids[1], 3)] {
        assert_eq!(
            verifier_normalized(
                logs_of(vector),
                EthereumEventSelectorV1::Void(EthereumLogRangeV1 {
                    first_log_index: 0,
                    log_count: count,
                })
            ),
            vector.get("normalized").cloned().expect("normalized")
        );
    }
    // TON transfers are proven from the minter's external-out body.
    assert_eq!(
        ton_verifier_normalized(&transfers[2]),
        transfers[2].get("normalized").cloned().expect("normalized")
    );
    assert_eq!(
        transfers
            .iter()
            .map(|vector| vector.get("source_profile").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [
            Some("ethereum-mainnet"),
            Some("bsc-mainnet"),
            Some("ton-mainnet")
        ],
        "one transfer vector per external source"
    );
    assert_eq!(voids.len(), 2, "the EVM expired and frozen voids");
    assert!(
        transfers
            .iter()
            .chain(voids)
            .all(|vector| vector.get("pending").is_none()),
        "no vector is pending"
    );
}

#[test]
#[ignore = "rewrites fixtures/sccp/native_transfer_event_v1.json; run only after a reviewed layout change"]
fn regenerate_native_transfer_event_v1() {
    let path = native_fixture_path();
    fs::write(&path, render(&native_transfer_event_fixture()))
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

#[test]
fn unsupported_networks_and_mismatched_frames_fail_closed() {
    let chain = SyntheticBeaconChainV1::mainnet();
    let now = chain.slot_unix_ms(slot(300));
    let memory = installed(&chain, now);
    let bytes = advance_bytes(&advance(&chain, &[update_spec(&chain, slot(200))]));
    assert_eq!(
        light_client::apply_advance(&memory, SccpNetworkV1::SoraTaira, &bytes, now),
        Err(SccpLcError::UnsupportedNetwork(SccpNetworkV1::SoraTaira))
    );
    for network in [SccpNetworkV1::BscMainnet, SccpNetworkV1::TonMainnet] {
        assert_eq!(
            light_client::apply_advance(&memory, network, &bytes, now),
            Err(SccpLcError::NotInstalled(network))
        );
    }
    let bootstrap = SccpLcBootstrapV1 {
        network: ETH,
        bytes: vec![1, 2, 3],
    };
    assert_eq!(
        light_client::verify_bootstrap(ETH, &params(), &bootstrap, now),
        Err(SccpLcError::MalformedFrame("bootstrap"))
    );
}
