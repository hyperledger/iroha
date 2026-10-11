//! TON evidence builders over the synthetic TON chain (spec §4.13.5, §11).
//!
//! The light client is bootstrapped at key block 100 (epoch 0) and hops to key block 200
//! (epoch 1). A burn registered by masterchain block 150 of epoch 0 is proven from that block's
//! own signatures across the hop while epoch 0 is fresh with the builder's margin, and through an
//! `OldMcBlocksInfo` back link from block 201 of epoch 1 afterwards. The synthetic source links
//! a key block forward only to blocks of its own epoch, as liteservers do. Every built proof is
//! verified by the production verifier through [`LightClientReplayV1`].

use std::collections::BTreeMap;

use iroha_data_model::sccp::light_client::SccpLightClientParamsV1;
use iroha_sccp::{
    light_client::{self as lc, SccpLcError, proof::SccpNormalizedEventV1},
    test_support::ton::{SYNTHETIC_STAKE_HELD_FOR, SyntheticTonChainV1, SyntheticTonEventV1},
    v1::payload::SccpTransferPayloadV1,
};

use super::*;
use crate::builders::LightClientReplayV1;

const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;
const T0: u32 = 1_790_000_000;
const UNTIL0: u32 = T0 + 65_536;
const UNTIL1: u32 = T0 + 80_000;
const MINTER: [u8; 32] = [0x4d; 32];
const LT: u64 = 500;

fn params() -> SccpLightClientParamsV1 {
    SccpLightClientParamsV1::defaults_for(TON).expect("external network")
}

fn profile() -> TonChainProfileV1 {
    SccpChainProfilesV1::latest().ton
}

/// TON data served from the synthetic chain.
#[derive(Default)]
struct SyntheticSource {
    blocks: BTreeMap<u32, TonBlockIdExtV1>,
    headers: BTreeMap<u32, Vec<u8>>,
    /// Target seqno → (the key block whose epoch signed it, signatures).
    signatures: BTreeMap<u32, (u32, TonBlockSignaturesV1)>,
    /// (fresh seqno, target seqno) → state proof.
    back_links: BTreeMap<(u32, u32), Vec<u8>>,
    burn: Option<TonBurnV1>,
}

impl SyntheticSource {
    fn add(&mut self, block: &TonSignedBlockV1, key: u32) {
        let seqno = block.block_id.seqno;
        self.blocks.insert(seqno, block.block_id);
        self.headers.insert(seqno, block.header_proof.clone());
        self.signatures
            .insert(seqno, (key, block.signatures.clone()));
    }
}

impl TonSource for SyntheticSource {
    fn masterchain_block(&self, seqno: u32) -> Result<TonBlockIdExtV1, BuildError> {
        self.blocks
            .get(&seqno)
            .copied()
            .ok_or_else(|| BuildError::Unavailable(format!("block {seqno} is not served")))
    }

    fn header_proof(&self, block: TonBlockIdExtV1) -> Result<Vec<u8>, BuildError> {
        self.headers
            .get(&block.seqno)
            .cloned()
            .ok_or_else(|| BuildError::Unavailable("header not served".into()))
    }

    fn signatures(
        &self,
        key: TonBlockIdExtV1,
        target: TonBlockIdExtV1,
    ) -> Result<TonBlockSignaturesV1, BuildError> {
        match self.signatures.get(&target.seqno) {
            Some((signer, signatures)) if *signer == key.seqno => Ok(signatures.clone()),
            _ => Err(BuildError::Unavailable(format!(
                "no forward link from key block {} to block {}",
                key.seqno, target.seqno
            ))),
        }
    }

    fn back_link_state_proof(
        &self,
        fresh: TonBlockIdExtV1,
        target: TonBlockIdExtV1,
    ) -> Result<Vec<u8>, BuildError> {
        self.back_links
            .get(&(fresh.seqno, target.seqno))
            .cloned()
            .ok_or_else(|| BuildError::Unavailable("no back link".into()))
    }

    fn burn(&self, minter: [u8; 32], lt: u64, _hash: [u8; 32]) -> Result<TonBurnV1, BuildError> {
        assert_eq!((minter, lt), (MINTER, LT));
        self.burn
            .clone()
            .ok_or_else(|| BuildError::Unavailable("not served".into()))
    }
}

const SENDER: [u8; 32] = [0x0a; 32];

/// The payload the minter builds for a burn of `amount` by [`SENDER`] under `nonce` (§5.3.4); the
/// verifier checks that the event's own fields agree with it.
fn burn_payload(nonce: u64, amount: u128) -> Vec<u8> {
    let mut sender = vec![0_u8; 4];
    sender.extend_from_slice(&SENDER);
    let mut recipient = vec![0x02, 0x01, 0x20];
    recipient.extend_from_slice(&[0x5a; 32]);
    SccpTransferPayloadV1::inbound(TON, nonce, 1, amount, sender, recipient)
        .and_then(|payload| payload.encode())
        .expect("valid payload")
}

fn transfer() -> SyntheticTonEventV1 {
    SyntheticTonEventV1::Transfer {
        message_id: [7; 32],
        nonce: 3,
        sender: SENDER,
        amount: 5_000_000_000,
        payload: burn_payload(3, 5_000_000_000),
    }
}

/// The burn in shard block 10 under shard block 11, registered by masterchain block `master`
/// (naming key block `prev_key`, signed by `epoch`).
fn burn(
    chain: &SyntheticTonChainV1,
    master: u32,
    prev_key: u32,
    epoch: u32,
) -> (TonBurnV1, TonSignedBlockV1) {
    let genesis = chain.genesis_shard();
    let event_block = chain.shard_block(
        10,
        &genesis,
        &genesis,
        &MINTER,
        Some(&(LT, transfer(), true)),
    );
    let top = chain.shard_block(11, &event_block.link.block_id, &genesis, &MINTER, None);
    let (signed, _) = chain.master_block(
        master,
        prev_key,
        epoch,
        T0 + 500,
        &top.link.block_id,
        &[],
        4,
    );
    (
        TonBurnV1 {
            masterchain: signed.block_id,
            shard_blocks: vec![top.link, event_block.link.clone()],
            event_block_proof: event_block.link.header_proof,
            transaction: event_block.transaction.expect("transaction"),
        },
        signed,
    )
}

/// A light client bootstrapped at key block 100 and hopped to key block 200, and the source of
/// a burn registered by block 150 of epoch 0 with block 201 of epoch 1 listing it.
fn hopped() -> (SyntheticSource, LightClientReplayV1) {
    let chain = SyntheticTonChainV1::new([4; 32]);
    let now = u64::from(T0) * 1_000 + 60_000;
    let initial = lc::verify_bootstrap(TON, &params(), &chain.bootstrap(100, 0, T0, UNTIL0), now)
        .expect("the bootstrap verifies");
    let mut replay = LightClientReplayV1::installed(TON, &initial);
    let key100 = chain.key_block(100, 90, 0, 0, T0, UNTIL0, 0);
    let key200 = chain.key_block(200, 100, 0, 1, T0 + 1_000, UNTIL1, 4);
    let hop = SccpLcAdvanceV1::Ton(TonLcAdvanceV1 {
        hops: vec![key200.hop.clone()],
    })
    .to_bytes()
    .expect("bounded");
    replay
        .advance(&hop, u64::from(T0 + 2_000) * 1_000)
        .expect("the hop verifies");
    assert_eq!(
        replay.light_client().expect("installed").head.latest_set_id,
        200
    );
    let (burn, registered) = burn(&chain, 150, 100, 0);
    let (fresh, state_proof) = chain.master_block(
        201,
        200,
        1,
        T0 + 1_100,
        &chain.genesis_shard(),
        &[registered.block_id],
        4,
    );
    let mut source = SyntheticSource {
        burn: Some(burn),
        ..SyntheticSource::default()
    };
    source.add(&key100.hop.block, 90);
    source.add(&key200.hop.block, 100);
    source.add(&registered, 100);
    source.add(&fresh, 200);
    source.back_links.insert((201, 150), state_proof);
    (source, replay)
}

/// The Taira time from which epoch 0 no longer signs.
fn epoch0_stale_from() -> u64 {
    (u64::from(UNTIL0) + u64::from(SYNTHETIC_STAKE_HELD_FOR)) * 1_000
        - profile().freshness_margin_ms
}

fn build(source: &SyntheticSource, replay: &LightClientReplayV1, now: u64) -> TonSourceProofV1 {
    let evidence = build_evidence(source, &profile(), (MINTER, LT, [0; 32], 0), replay, now)
        .expect("evidence");
    assert!(evidence.backfills.is_empty());
    let verified = replay
        .verify_evidence(&evidence, now)
        .expect("the evidence verifies");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::TransferToTaira { nonce: 3, .. }
    ));
    let SccpSourceProofV1::Ton(proof) =
        SccpSourceProofV1::from_frame(evidence.proof.as_bytes()).expect("proof frame")
    else {
        panic!("a TON proof");
    };
    proof
}

#[test]
fn burns_keep_their_own_signed_block_across_a_key_block_hop() {
    let (source, replay) = hopped();
    assert_eq!(
        epoch_stale_from_ms(&profile(), &replay.sets().expect("sets"), 100),
        Some(epoch0_stale_from())
    );
    let now = epoch0_stale_from() - FRESHNESS_MARGIN_MS - 1;
    let proof = build(&source, &replay, now);
    let TonMasterchainAnchorV1::Signed(signed) = &proof.masterchain else {
        panic!("a signed anchor");
    };
    assert_eq!(signed.block_id.seqno, 150);
    // Past epoch 0's freshness the signed anchor is refused by the verifier.
    let bytes = SccpSourceProofV1::Ton(proof).to_bytes().expect("bounded");
    assert!(matches!(
        lc::verify_proof(replay.state(), TON, &bytes, epoch0_stale_from()),
        Err(SccpLcError::StaleSigningSet { set_id: 100, .. })
    ));
}

#[test]
fn older_burns_hang_from_a_back_link_of_the_newest_epoch() {
    let (source, replay) = hopped();
    let edge = epoch0_stale_from() - FRESHNESS_MARGIN_MS;
    let proof = build(&source, &replay, edge);
    let TonMasterchainAnchorV1::BackLink(link) = &proof.masterchain else {
        panic!("a back link");
    };
    assert_eq!(link.fresh.block_id.seqno, 201);
    assert_eq!(link.block_id.seqno, 150);
    // The back-linked proof still verifies once epoch 0 is stale.
    let bytes = SccpSourceProofV1::Ton(proof).to_bytes().expect("bounded");
    assert!(lc::verify_proof(replay.state(), TON, &bytes, epoch0_stale_from()).is_ok());
}

#[test]
fn burns_in_an_unlearned_epoch_need_an_advance_first() {
    let chain = SyntheticTonChainV1::new([5; 32]);
    let now = u64::from(T0) * 1_000 + 60_000;
    let initial = lc::verify_bootstrap(TON, &params(), &chain.bootstrap(100, 0, T0, UNTIL0), now)
        .expect("the bootstrap verifies");
    let replay = LightClientReplayV1::installed(TON, &initial);
    let (burn, registered) = burn(&chain, 250, 200, 1);
    let mut source = SyntheticSource {
        burn: Some(burn),
        ..SyntheticSource::default()
    };
    source.add(&registered, 200);
    let error = build_evidence(&source, &profile(), (MINTER, LT, [0; 32], 0), &replay, now)
        .expect_err("epoch 1 is not stored");
    assert!(error.to_string().contains("advance it first"), "{error}");
    assert_eq!(epoch_stale_from_ms(&profile(), &[], 100), None);
}
