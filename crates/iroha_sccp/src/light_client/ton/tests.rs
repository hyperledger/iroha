//! Tests of the TON light client against the synthetic chain of `test_support::ton`.

use super::*;
use crate::{
    light_client::{
        SccpLcAdvanceV1, SccpLcEvidenceV1, SccpSourceProofV1, apply_advance_with_profiles,
        initialize_light_client_with_profiles, profile::SccpChainProfilesV1,
        state::SccpLcMemoryStateV1, verify_equivocation_with_profiles, verify_proof_with_profiles,
    },
    test_support::ton::{SYNTHETIC_STAKE_HELD_FOR, SyntheticTonChainV1, SyntheticTonEventV1},
};
use iroha_data_model::sccp::light_client::SccpLcInitExpectationV1;

use crate::v1::payload::SccpTransferPayloadV1;

const T0: u32 = 1_790_000_000;
const UNTIL0: u32 = T0 + 65_536;
const MINTER: [u8; 32] = [0x4d; 32];
const OWNER: [u8; 32] = [0x0a; 32];
/// A Taira time after every synthetic block of the tests.
const LATER_MS: u64 = (T0 as u64 + 2_000) * 1_000;

fn profiles() -> SccpChainProfilesV1 {
    *SccpChainProfilesV1::genesis()
}

fn params() -> SccpLightClientParamsV1 {
    SccpLightClientParamsV1::defaults_for(NETWORK).expect("external")
}

fn installed(chain: &SyntheticTonChainV1) -> (SccpLcMemoryStateV1, u64) {
    let now = u64::from(T0) * 1_000 + 60_000;
    let mut memory = SccpLcMemoryStateV1::new();
    let initial = initialize_light_client_with_profiles(
        &profiles(),
        &memory,
        NETWORK,
        SccpLcInitExpectationV1::Absent,
        &params(),
        &chain.bootstrap(100, 0, T0, UNTIL0),
        now,
    )
    .expect("bootstrap verifies");
    memory.install(NETWORK, &initial);
    (memory, now)
}

fn advance(
    memory: &mut SccpLcMemoryStateV1,
    hops: Vec<TonKeyBlockHopV1>,
    now: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    let bytes = SccpLcAdvanceV1::Ton(TonLcAdvanceV1 { hops })
        .to_bytes()
        .expect("bounded");
    let delta = apply_advance_with_profiles(&profiles(), memory, NETWORK, &bytes, now)?;
    memory.apply(NETWORK, &delta);
    Ok(delta)
}

#[test]
fn bootstrap_installs_the_key_block_epoch_until_its_stake_is_released() {
    let chain = SyntheticTonChainV1::new([1; 32]);
    let (memory, _) = installed(&chain);
    let now = LATER_MS;
    let light_client = memory.light_client(NETWORK).expect("installed");
    assert_eq!(light_client.head.latest_set_id, 100);
    let epoch = decode_epoch(&memory.consensus_set(NETWORK, 100).expect("epoch")).expect("decodes");
    assert_eq!(epoch.validators.validators.len(), 5);
    assert_eq!(epoch.stake_held_for, SYNTHETIC_STAKE_HELD_FOR);
    let deadline = weak_subjectivity_deadline_ms(&profiles().ton, &memory, &light_client);
    assert_eq!(
        deadline,
        (u64::from(UNTIL0) + u64::from(SYNTHETIC_STAKE_HELD_FOR)) * 1_000 - 3_600_000
    );
    assert!(!is_aged(&profiles().ton, &memory, &light_client, now));
    assert!(is_aged(&profiles().ton, &memory, &light_client, deadline));
    assert_eq!(aged_supersessions(&memory, &light_client).len(), 1);
    assert!(matches!(
        initialize_light_client_with_profiles(
            &profiles(),
            &SccpLcMemoryStateV1::new(),
            NETWORK,
            SccpLcInitExpectationV1::Absent,
            &params(),
            &chain.bootstrap(100, 0, T0, UNTIL0),
            deadline,
        ),
        Err(SccpLcError::StaleSigningSet { set_id: 100, .. })
    ));
}

#[test]
fn key_block_hops_are_signed_by_the_previous_epoch_in_order() {
    let chain = SyntheticTonChainV1::new([2; 32]);
    let (mut memory, now) = installed(&chain);
    let first = chain.key_block(200, 100, 0, 1, T0 + 1_000, T0 + 80_000, 4);
    let second = chain.key_block(300, 200, 1, 2, T0 + 2_000, T0 + 90_000, 4);
    let later = now + 2_000_000;
    let delta = advance(
        &mut memory,
        vec![first.hop.clone(), second.hop.clone()],
        later,
    )
    .expect("two hops");
    assert_eq!(delta.new_sets.len(), 2);
    assert_eq!(
        delta.new_sets[0].superseded_at_source_ms,
        Some(u64::from(T0 + 2_000) * 1_000)
    );
    assert_eq!(delta.superseded_sets[0].set_id, 100);
    let head = delta.head.expect("moved");
    assert_eq!(head.latest_set_id, 300);
    assert_eq!(head.latest_finalized.source_height, 300);
    let again = advance(&mut memory, vec![second.hop], later).expect("idempotent re-proof");
    assert!(again.new_sets.is_empty());
}

#[test]
fn hops_need_a_quorum_and_the_next_key_block() {
    let chain = SyntheticTonChainV1::new([3; 32]);
    let (mut memory, _) = installed(&chain);
    let now = LATER_MS;
    let thin = chain.key_block(200, 100, 0, 1, T0 + 1_000, T0 + 80_000, 3);
    assert_eq!(
        advance(&mut memory, vec![thin.hop], now),
        Err(TonLcError::Native(TonNativeSourceError::InvalidSignatures).into())
    );
    let skipping = chain.key_block(300, 150, 0, 1, T0 + 1_000, T0 + 80_000, 5);
    assert!(matches!(
        advance(&mut memory, vec![skipping.hop], now),
        Err(SccpLcError::UnknownSigningSet { set_id: 150 })
    ));
    let wrong_signers = chain.key_block(200, 100, 1, 1, T0 + 1_000, T0 + 80_000, 5);
    assert!(advance(&mut memory, vec![wrong_signers.hop], now).is_err());
    assert!(matches!(
        advance(&mut memory, Vec::new(), now),
        Err(SccpLcError::TooFewItems { .. })
    ));
}

/// The payload the minter builds for a burn of `amount` by `OWNER` under `nonce` (§5.3.4).
fn burn_payload(nonce: u64, amount: u128) -> Vec<u8> {
    let mut sender = vec![0_u8; 4];
    sender.extend_from_slice(&OWNER);
    let mut recipient = vec![0x02, 0x01, 0x20];
    recipient.extend_from_slice(&[0x5a; 32]);
    SccpTransferPayloadV1::inbound(NETWORK, nonce, 1, amount, sender, recipient)
        .and_then(|payload| payload.encode())
        .expect("valid payload")
}

fn transfer() -> SyntheticTonEventV1 {
    SyntheticTonEventV1::Transfer {
        message_id: [7; 32],
        nonce: 3,
        sender: OWNER,
        amount: 5_000_000_000,
        payload: burn_payload(3, 5_000_000_000),
    }
}

/// A proof of `event` in shard block 10 under shard block 11, registered by masterchain block
/// 150 signed by epoch 0.
fn event_proof(
    chain: &SyntheticTonChainV1,
    event: SyntheticTonEventV1,
    succeed: bool,
) -> TonSourceProofV1 {
    let anchor_ref = chain.genesis_shard();
    let genesis = chain.genesis_shard();
    let event_block = chain.shard_block(
        10,
        &genesis,
        &anchor_ref,
        &MINTER,
        Some(&(500, event, succeed)),
    );
    let top = chain.shard_block(11, &event_block.link.block_id, &anchor_ref, &MINTER, None);
    let (master, _) = chain.master_block(150, 100, 0, T0 + 500, &top.link.block_id, &[], 4);
    TonSourceProofV1 {
        masterchain: TonMasterchainAnchorV1::Signed(master),
        shard_blocks: vec![top.link, event_block.link.clone()],
        event_block_proof: event_block.link.header_proof,
        transaction: event_block.transaction.expect("transaction"),
        transaction_lt: 500,
        message_index: 0,
        minter: MINTER,
    }
}

fn verify(
    memory: &SccpLcMemoryStateV1,
    proof: &TonSourceProofV1,
    now: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    let bytes = SccpSourceProofV1::Ton(proof.clone())
        .to_bytes()
        .expect("bounded");
    verify_proof_with_profiles(&profiles(), memory, NETWORK, &bytes, now)
}

#[test]
fn proofs_walk_the_shard_chain_to_the_minter_transaction() {
    let chain = SyntheticTonChainV1::new([4; 32]);
    let (memory, _) = installed(&chain);
    let now = LATER_MS;
    let proof = event_proof(&chain, transfer(), true);
    let verified = verify(&memory, &proof, now).expect("proof verifies");
    let SccpNormalizedEventV1::TransferToTaira {
        emitter,
        message_id,
        sender,
        nonce,
        payload_hash: hash,
        locator,
    } = verified.event
    else {
        panic!("transfer expected");
    };
    assert_eq!(emitter, SccpSourceEmitterV1::Ton(MINTER));
    assert_eq!(message_id, [7; 32]);
    assert_eq!(nonce, 3);
    assert_eq!(sender.codec, CODEC_TON_ACCOUNT36);
    assert_eq!(&sender.bytes[4..], &OWNER);
    assert_eq!(hash, payload_hash(&burn_payload(3, 5_000_000_000)));
    assert_eq!(locator.source_height, 10);
    let mut swapped = proof.clone();
    swapped.shard_blocks.reverse();
    assert_eq!(
        verify(&memory, &swapped, now),
        Err(TonLcError::BrokenShardWalk { index: 0 }.into())
    );
    let mut other_minter = proof;
    other_minter.minter = [0x4e; 32];
    assert!(matches!(
        verify(&memory, &other_minter, now),
        Err(SccpLcError::Ton(TonLcError::Native(_)))
    ));
}

#[test]
fn failed_transactions_and_void_events_are_classified() {
    let chain = SyntheticTonChainV1::new([5; 32]);
    let (memory, _) = installed(&chain);
    let now = LATER_MS;
    assert_eq!(
        verify(&memory, &event_proof(&chain, transfer(), false), now),
        Err(TonLcError::Native(TonNativeSourceError::UnsuccessfulTransaction).into())
    );
    let void = SyntheticTonEventV1::Voided {
        message_id: [0; 32],
        first_nonce: 4,
        count: 2,
    };
    let verified = verify(&memory, &event_proof(&chain, void, true), now).expect("void");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::Void {
            kind: SccpVoidKindV1::Frozen,
            first_nonce: 4,
            count: 2,
            ..
        }
    ));
}

#[test]
fn back_links_reach_older_masterchain_blocks() {
    let chain = SyntheticTonChainV1::new([6; 32]);
    let (memory, _) = installed(&chain);
    let now = LATER_MS;
    let proof = event_proof(&chain, transfer(), true);
    let TonMasterchainAnchorV1::Signed(old) = proof.masterchain.clone() else {
        panic!("signed anchor");
    };
    let (fresh, state_proof) = chain.master_block(
        180,
        100,
        0,
        T0 + 900,
        &chain.genesis_shard(),
        &[old.block_id],
        4,
    );
    let mut linked = proof.clone();
    linked.masterchain = TonMasterchainAnchorV1::BackLink(TonBackLinkV1 {
        fresh: fresh.clone(),
        state_proof: state_proof.clone(),
        block_id: old.block_id,
        header_proof: old.header_proof.clone(),
    });
    let verified = verify(&memory, &linked, now).expect("back-linked proof");
    assert_eq!(verified.event.locator().source_height, 10);
    let mut wrong = linked;
    let TonMasterchainAnchorV1::BackLink(link) = &mut wrong.masterchain else {
        panic!("back link");
    };
    link.block_id.seqno = 151;
    assert!(verify(&memory, &wrong, now).is_err());
}

#[test]
fn conflicting_signed_blocks_freeze_the_light_client() {
    let chain = SyntheticTonChainV1::new([7; 32]);
    let (memory, _) = installed(&chain);
    let now = LATER_MS;
    let (a, _) = chain.master_block(150, 100, 0, T0 + 500, &chain.genesis_shard(), &[], 4);
    let other_shard = chain.shard_block(
        2,
        &chain.genesis_shard(),
        &chain.genesis_shard(),
        &MINTER,
        None,
    );
    let (b, _) = chain.master_block(150, 100, 0, T0 + 500, &other_shard.link.block_id, &[], 4);
    let first = SccpLcEvidenceV1::Ton(TonLcEvidenceV1 { block: a.clone() })
        .to_bytes()
        .expect("bounded");
    let second = SccpLcEvidenceV1::Ton(TonLcEvidenceV1 { block: b })
        .to_bytes()
        .expect("bounded");
    let reason =
        verify_equivocation_with_profiles(&profiles(), &memory, NETWORK, &first, &second, now)
            .expect("conflict");
    assert!(matches!(reason, SccpLcFreezeReasonV1::Equivocation(_)));
    assert_eq!(
        verify_equivocation_with_profiles(&profiles(), &memory, NETWORK, &first, &first, now),
        Err(SccpLcError::EvidenceNotConflicting)
    );
    let work = evidence_work(&TonLcEvidenceV1 { block: a });
    assert_eq!(work.ed25519_signature_checks, 4);
}

#[test]
fn transfer_events_must_carry_their_own_payload_fields() {
    let chain = SyntheticTonChainV1::new([8; 32]);
    let (memory, _) = installed(&chain);
    let now = LATER_MS;
    let mismatched = |nonce: u64, sender: [u8; 32], amount: u128, payload: Vec<u8>| {
        SyntheticTonEventV1::Transfer {
            message_id: [7; 32],
            nonce,
            sender,
            amount,
            payload,
        }
    };
    for (label, event) in [
        (
            "amount",
            mismatched(3, OWNER, 4_999_999_999, burn_payload(3, 5_000_000_000)),
        ),
        (
            "nonce",
            mismatched(4, OWNER, 5_000_000_000, burn_payload(3, 5_000_000_000)),
        ),
        (
            "sender",
            mismatched(3, [0x0b; 32], 5_000_000_000, burn_payload(3, 5_000_000_000)),
        ),
        (
            "payload",
            mismatched(3, OWNER, 5_000_000_000, (0..200_u8).collect()),
        ),
    ] {
        assert_eq!(
            verify(&memory, &event_proof(&chain, event, true), now),
            Err(TonLcError::MalformedEvent.into()),
            "{label}"
        );
    }
    assert!(verify(&memory, &event_proof(&chain, transfer(), true), now).is_ok());
}

#[test]
fn captured_mainnet_key_block_bootstraps_and_its_epoch_verifies_a_signed_block() {
    use crate::test_support::ton_capture::{
        CAPTURED_ACCOUNT, CAPTURED_BLOCK_SEQNO, CAPTURED_KEY_BLOCK_SEQNO, CAPTURED_TRANSACTION_LT,
        forward_link, full_block, key_block_bootstrap, transaction,
    };
    let link = forward_link("get_block_proof_forward");
    assert_eq!(link.to.seqno, CAPTURED_BLOCK_SEQNO);
    let block = TonSignedBlockV1 {
        block_id: link.to,
        header_proof: link.dest_proof.clone(),
        signatures: link.signatures.clone(),
    };
    let (header, _) =
        ton_open_masterchain_block(block.block_id, &block.header_proof, None).expect("header");
    let now = u64::from(header.gen_utime) * 1_000 + 60_000;
    let bootstrap = crate::light_client::SccpLcBootstrapDataV1::Ton(key_block_bootstrap())
        .to_bootstrap()
        .expect("frame");
    let mut memory = SccpLcMemoryStateV1::new();
    let initial = initialize_light_client_with_profiles(
        &profiles(),
        &memory,
        NETWORK,
        SccpLcInitExpectationV1::Absent,
        &params(),
        &bootstrap,
        now,
    )
    .expect("the captured key block bootstraps");
    memory.install(NETWORK, &initial);
    let light_client = memory.light_client(NETWORK).expect("installed");
    assert_eq!(
        light_client.head.latest_set_id,
        u64::from(CAPTURED_KEY_BLOCK_SEQNO)
    );
    // Fresh until (utime_until + stake_held_for) · 1000 − 1 h.
    assert_eq!(
        weak_subjectivity_deadline_ms(&profiles().ton, &memory, &light_client),
        (1_790_529_288 + 32_768) * 1_000 - 3_600_000
    );

    // Two records of the same block with different header proofs (the liteserver's pruned
    // header proof and the full block): both verify under the stored epoch and do not conflict.
    let (full_id, full) = full_block();
    assert_eq!(full_id, block.block_id);
    let record = |block: TonSignedBlockV1| {
        SccpLcEvidenceV1::Ton(TonLcEvidenceV1 { block })
            .to_bytes()
            .expect("bounded")
    };
    let pruned = record(block.clone());
    let complete = record(TonSignedBlockV1 {
        header_proof: full.clone(),
        ..block.clone()
    });
    assert_eq!(
        verify_equivocation_with_profiles(&profiles(), &memory, NETWORK, &pruned, &complete, now),
        Err(SccpLcError::EvidenceNotConflicting)
    );
    let TonBlockSignaturesV1::Simplex(mut forged) = link.signatures.clone() else {
        panic!("mainnet signs under Simplex");
    };
    forged.signatures[0].signature[1] ^= 1;
    let forged = record(TonSignedBlockV1 {
        signatures: TonBlockSignaturesV1::Simplex(forged),
        ..block.clone()
    });
    assert_eq!(
        verify_equivocation_with_profiles(&profiles(), &memory, NETWORK, &pruned, &forged, now),
        Err(TonLcError::Native(TonNativeSourceError::InvalidSignatures).into())
    );

    // A proof anchored at the signed full block passes the signatures and the shard
    // registration; the recorded transaction's block is not the shard's top block in `B`.
    let transaction = transaction();
    let proof = TonSourceProofV1 {
        masterchain: TonMasterchainAnchorV1::Signed(TonSignedBlockV1 {
            header_proof: full,
            ..block
        }),
        shard_blocks: vec![TonShardLinkV1 {
            block_id: transaction.block,
            header_proof: transaction.proof.clone(),
        }],
        event_block_proof: transaction.proof,
        transaction: transaction.transaction,
        transaction_lt: CAPTURED_TRANSACTION_LT,
        message_index: 0,
        minter: CAPTURED_ACCOUNT,
    };
    assert_eq!(
        verify(&memory, &proof, now),
        Err(TonLcError::BrokenShardWalk { index: 0 }.into())
    );
}
