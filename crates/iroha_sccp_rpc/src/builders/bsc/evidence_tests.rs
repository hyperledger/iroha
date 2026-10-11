//! BSC advance and evidence builders over the synthetic Parlia chain (spec §4.13.5, §11).
//!
//! The light client is bootstrapped at the epoch checkpoint 5 000 and advanced through the set
//! transition announced at the epoch checkpoint 7 000, which the advance records. A burn under
//! the superseded set is proven by a vote attestation while that set is still fresh with the
//! builder's margin, and from the recorded epoch checkpoint afterwards: directly 255 blocks
//! below it, with one `Backfill` 256 blocks below it. Every built piece is verified by the
//! production verifier through [`LightClientReplayV1`].

use std::collections::BTreeMap;

use iroha_data_model::sccp::light_client::SccpLightClientParamsV1;
use iroha_sccp::{
    light_client::{
        self as lc, SccpLcStateView as _, profile::BSC_MAINNET, proof::SccpNormalizedEventV1,
    },
    test_support::{
        bsc::SyntheticParliaChainV1,
        ethereum::{receipt_root_and_proof, successful_receipt, transfer_log},
    },
    v1::evm_abi::TransferToTairaLogV1,
};

use super::*;
use crate::builders::{FRESHNESS_MARGIN_MS, LightClientReplayV1};

const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
const EMITTER: [u8; 20] = [0x42; 20];
/// The epoch checkpoint announcing the second roster.
const TRANSITION: u64 = 7_000;

fn params() -> SccpLightClientParamsV1 {
    SccpLightClientParamsV1::defaults_for(BSC).expect("external network")
}

/// BSC data served from the synthetic chain: every attestation is signed by the full roster
/// covering its target.
struct ParliaSource {
    chain: SyntheticParliaChainV1,
    finalized: u64,
    events: BTreeMap<[u8; 32], EvmEventBlockV1>,
    /// `(first covered height, announcing checkpoint)` of each roster, ascending.
    rosters: Vec<(u64, u64)>,
}

impl BscSource for ParliaSource {
    fn finalized_number(&self) -> Result<u64, BuildError> {
        Ok(self.finalized)
    }

    fn latest_number(&self) -> Result<u64, BuildError> {
        Ok(self.finalized + 2)
    }

    fn headers_at(&self, numbers: &[u64]) -> Result<Vec<Vec<u8>>, BuildError> {
        Ok(numbers
            .iter()
            .map(|number| self.chain.header(*number).rlp)
            .collect())
    }

    fn event_block(&self, tx_hash: &[u8; 32]) -> Result<EvmEventBlockV1, BuildError> {
        self.events
            .get(tx_hash)
            .cloned()
            .ok_or_else(|| BuildError::Unavailable("not mined".into()))
    }

    fn finalizing_vote(&self, from: u64, _until: u64) -> Result<(Vec<u8>, BscVoteV1), BuildError> {
        let set_height = self
            .rosters
            .iter()
            .rev()
            .find(|(covers, _)| *covers <= from + 1)
            .map(|(_, checkpoint)| *checkpoint)
            .ok_or_else(|| BuildError::Unavailable("no roster covers the target".into()))?;
        Ok((
            self.chain.attestation(set_height, usize::MAX, from),
            BscVoteV1 {
                source_number: from,
                source_hash: self.chain.header(from).hash,
                target_number: from + 1,
                target_hash: self.chain.header(from + 1).hash,
            },
        ))
    }
}

fn tx(height: u64) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash[..8].copy_from_slice(&height.to_be_bytes());
    hash
}

/// The chain with burns at `burns`, a light client bootstrapped at epoch 5 and advanced by the
/// builder through the transition at 7 000.
fn advanced(burns: &[u64]) -> (ParliaSource, LightClientReplayV1) {
    let log = TransferToTairaLogV1 {
        message_id: [9; 32],
        sender: [3; 20],
        nonce: 4,
        payload: vec![1, 2, 3],
    };
    let (root, receipt_proof) =
        receipt_root_and_proof(&[successful_receipt(vec![transfer_log(EMITTER, &log)])], 0);
    let mut chain = SyntheticParliaChainV1::new([9; 32], 21, 16).with_transition(7, 1, 21, 16);
    for burn in burns {
        chain = chain.with_receipts_root(*burn, root);
    }
    let events = burns
        .iter()
        .map(|burn| {
            (
                tx(*burn),
                EvmEventBlockV1 {
                    header: chain.header(*burn).rlp,
                    number: *burn,
                    transaction_index: 0,
                    receipt_proof: receipt_proof.clone(),
                },
            )
        })
        .collect();
    let now = SyntheticParliaChainV1::time_ms(5_000) + 1_000;
    let initial = lc::verify_bootstrap(BSC, &params(), &chain.bootstrap(5), now)
        .expect("the bootstrap verifies");
    let mut replay = LightClientReplayV1::installed(BSC, &initial);
    let source = ParliaSource {
        chain,
        finalized: TRANSITION + 10,
        events,
        rosters: vec![(5_176, 5_000), (TRANSITION + 176, TRANSITION)],
    };
    let budget = AdvanceBudgetV1::for_params(&params(), 262_144);
    let advance = build_advance(&source, &BSC_MAINNET, 5_000, budget).expect("advance");
    let at = SyntheticParliaChainV1::time_ms(TRANSITION + 11) + 1_000;
    let delta = replay
        .advance(&advance, at)
        .expect("the transition verifies");
    assert_eq!(delta.new_sets.len(), 1);
    let head = replay.light_client().expect("installed").head;
    assert_eq!(head.latest_set_id, TRANSITION);
    assert!(
        replay
            .state()
            .checkpoint(BSC, TRANSITION)
            .is_some_and(
                |checkpoint| checkpoint.data.block_hash == source.chain.header(TRANSITION).hash
            ),
        "the advance records the epoch checkpoint"
    );
    (source, replay)
}

/// The edge from which the superseded set no longer anchors evidence: `ws_bound_ms` after the
/// transition checkpoint's time, less the builder's margin.
fn stale_edge() -> u64 {
    SyntheticParliaChainV1::time_ms(TRANSITION) + params().ws_bound_ms - FRESHNESS_MARGIN_MS
}

fn decoded(evidence: &SourceEvidenceV1) -> BscSourceProofV1 {
    let SccpSourceProofV1::Bsc(proof) =
        SccpSourceProofV1::from_frame(evidence.proof.as_bytes()).expect("proof frame")
    else {
        panic!("a BSC proof");
    };
    proof
}

fn build(
    source: &ParliaSource,
    replay: &LightClientReplayV1,
    burn: u64,
    now: u64,
) -> SourceEvidenceV1 {
    let evidence = build_evidence(
        source,
        &tx(burn),
        EthereumEventV1::TransferToTaira { log_index: 0 },
        replay,
        now,
    )
    .expect("evidence");
    let verified = replay
        .verify_evidence(&evidence, now)
        .expect("the evidence verifies");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::TransferToTaira { nonce: 4, .. }
    ));
    assert_eq!(verified.event.locator().source_height, burn);
    evidence
}

#[test]
fn fresh_sets_anchor_a_vote_and_stale_ones_the_epoch_checkpoint() {
    let (source, replay) = advanced(&[6_900]);
    let fresh = build(&source, &replay, 6_900, stale_edge() - 1);
    assert!(fresh.backfills.is_empty());
    let proof = decoded(&fresh);
    assert_eq!(
        proof.anchor,
        BscProofAnchorV1::Finality(BscFinalityV1 {
            set_id: 5_000,
            successor_set_id: Some(TRANSITION),
            attestation: source.chain.attestation(5_000, usize::MAX, 6_900),
        })
    );
    assert_eq!(proof.headers.len(), 1);
    let stale = build(&source, &replay, 6_900, stale_edge());
    assert!(stale.backfills.is_empty());
    let proof = decoded(&stale);
    assert_eq!(
        proof.anchor,
        BscProofAnchorV1::StoredCheckpoint(BscStoredCheckpointRefV1 {
            source_height: TRANSITION,
        })
    );
    assert_eq!(proof.headers.len(), 101);
}

#[test]
fn the_epoch_checkpoint_reaches_255_blocks_directly_and_256_with_one_backfill() {
    let (source, replay) = advanced(&[TRANSITION - 255, TRANSITION - 256]);
    let direct = build(&source, &replay, TRANSITION - 255, stale_edge());
    assert!(direct.backfills.is_empty());
    assert_eq!(decoded(&direct).headers.len(), 256);
    let backfilled = build(&source, &replay, TRANSITION - 256, stale_edge());
    assert_eq!(backfilled.backfills.len(), 1);
    let proof = decoded(&backfilled);
    assert_eq!(
        proof.anchor,
        BscProofAnchorV1::StoredCheckpoint(BscStoredCheckpointRefV1 {
            source_height: TRANSITION - 255,
        })
    );
    assert_eq!(proof.headers.len(), 2);
}

#[test]
fn burns_without_a_fresh_set_or_checkpoint_are_unavailable() {
    let (source, replay) = advanced(&[6_900]);
    let bare = LightClientReplayV1::new(
        BSC,
        replay.light_client().expect("installed"),
        replay.sets().expect("sets"),
        Vec::new(),
    );
    assert!(matches!(
        build_evidence(
            &source,
            &tx(6_900),
            EthereumEventV1::TransferToTaira { log_index: 0 },
            &bare,
            stale_edge(),
        ),
        Err(BuildError::Unavailable(_))
    ));
    assert!(matches!(
        build_evidence(
            &source,
            &tx(1),
            EthereumEventV1::TransferToTaira { log_index: 0 },
            &replay,
            stale_edge(),
        ),
        Err(BuildError::Unavailable(_))
    ));
}

#[test]
fn unchanged_sets_advance_from_the_newest_finalized_epoch_checkpoint() {
    let (mut source, mut replay) = advanced(&[]);
    let budget = AdvanceBudgetV1::for_params(&params(), 262_144);
    // No epoch checkpoint after the newest set's own is finalized yet: nothing refreshes it.
    assert!(matches!(
        build_advance(&source, &BSC_MAINNET, TRANSITION, budget),
        Err(BuildError::Unavailable(_))
    ));
    // The next finalized epoch checkpoint re-announces the newest set; the advance steps from it
    // to a finalized descendant, so it becomes the head the newest set's freshness counts from.
    let next = TRANSITION + BSC_MAINNET.epoch_length;
    source.finalized = next + 10;
    let advance = build_advance(&source, &BSC_MAINNET, TRANSITION, budget).expect("advance");
    let at = SyntheticParliaChainV1::time_ms(next + 11) + 1_000;
    let delta = replay.advance(&advance, at).expect("the refresh verifies");
    assert!(delta.new_sets.is_empty());
    let head = replay.light_client().expect("installed").head;
    assert_eq!(head.latest_set_id, TRANSITION);
    assert_eq!(head.latest_finalized.source_height, next);
    assert_eq!(
        head.latest_finalized.block_hash,
        source.chain.header(next).hash
    );
}
