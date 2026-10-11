//! Genuine native certificates exercise replay milestones, restart custody and fork refusal.

use super::*;
use crate::attachment::tests::Fixture;
use iroha_data_model::sumeragi_finality::SumeragiFinalityProof;
use iroha_model_base::peer::PeerId;
use std::{cell::RefCell, collections::BTreeMap};

#[derive(Default)]
struct Source {
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    reads: RefCell<Vec<u64>>,
}
impl Source {
    fn retain(&mut self, fixture: &Fixture) {
        let checkpoint = fixture.parent.checkpoint();
        self.proofs
            .insert(checkpoint.height(), checkpoint.tip().clone());
    }
}
impl FinalitySource for Source {
    type Error = std::io::Error;
    fn finality_proof(
        &self,
        height: NonZeroU64,
    ) -> std::result::Result<SumeragiFinalityProof, Self::Error> {
        self.reads.borrow_mut().push(height.get());
        self.proofs
            .get(&height.get())
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing fixture proof"))
    }
    fn latest_attestation(
        &self,
        _: &PeerId,
        _: &[u8; 32],
    ) -> std::result::Result<crate::verify::finality::FinalityAttestation, Self::Error> {
        Err(std::io::Error::other(
            "replay must not replace its captured comparison",
        ))
    }
}
fn original(fixture: &Fixture) -> FinalityVerifier {
    FinalityVerifier::from_checkpoint(
        fixture.parent.checkpoint(),
        fixture.parent.network_id(),
        fixture.parent.chain_id(),
    )
    .unwrap()
}
fn reopened(replay: &ParentReplay, fixture: &Fixture, initial: &FinalityVerifier) -> ParentReplay {
    let bytes = norito::encode_canonical(replay).unwrap();
    let replay: ParentReplay =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    replay.validate(&fixture.identity, initial).unwrap();
    replay
}

#[test]
fn original_carrier_is_retained_before_later_comparison_and_survives_restart() {
    let mut fixture = Fixture::new();
    let initial = original(&fixture);
    let mut source = Source::default();
    let (receipt, _) = fixture.parent_receipt();
    source.retain(&fixture);
    fixture.parent_receipt();
    source.retain(&fixture);
    let (_, comparison) = fixture.parent_receipt();
    source.retain(&fixture);
    let mut replay = ParentReplay::new(
        &fixture.identity,
        &initial,
        NonZeroU64::new(2).unwrap(),
        &comparison,
    )
    .unwrap();
    replay.advance_page(&fixture.identity, &source).unwrap();
    assert_eq!(*source.reads.borrow(), [2]);
    assert!(replay.completed(&fixture.identity).unwrap().is_none());
    assert_eq!(replay.needs_carrier_proof().unwrap().get(), 2);
    // Neither repeated calls nor a later source tip can skip an unavailable original write.
    replay.advance_page(&fixture.identity, &source).unwrap();
    assert_eq!(*source.reads.borrow(), [2]);
    let mut replay = reopened(&replay, &fixture, &initial);
    replay
        .retain_carrier(&fixture.identity, receipt.clone())
        .unwrap();
    let mut replay = reopened(&replay, &fixture, &initial);
    replay.advance_page(&fixture.identity, &source).unwrap();
    assert_eq!(*source.reads.borrow(), [2, 3, 4]);
    let replay = reopened(&replay, &fixture, &initial);
    let (actual, carrier) = replay.completed(&fixture.identity).unwrap().unwrap();
    assert_eq!(actual, receipt);
    assert_eq!(carrier.checkpoint().height(), 2);
    assert_eq!(
        decode_checkpoint(&fixture.identity, &replay.progress)
            .unwrap()
            .checkpoint()
            .height(),
        4
    );
}

#[test]
fn earlier_comparison_is_checked_before_a_later_carrier_without_skipping_a_milestone() {
    let mut fixture = Fixture::new();
    let initial = original(&fixture);
    let mut source = Source::default();
    let (_, comparison) = fixture.parent_receipt();
    source.retain(&fixture);
    let (receipt, _) = fixture.parent_receipt();
    source.retain(&fixture);
    let mut replay = ParentReplay::new(
        &fixture.identity,
        &initial,
        NonZeroU64::new(3).unwrap(),
        &comparison,
    )
    .unwrap();
    replay.advance_page(&fixture.identity, &source).unwrap();
    assert_eq!(*source.reads.borrow(), [2]);
    assert!(replay.comparison_verified);
    assert!(replay.needs_carrier_proof().is_none());
    let mut replay = reopened(&replay, &fixture, &initial);
    replay.advance_page(&fixture.identity, &source).unwrap();
    replay.retain_carrier(&fixture.identity, receipt).unwrap();
    assert!(replay.completed(&fixture.identity).unwrap().is_some());
    assert_eq!(*source.reads.borrow(), [2, 3]);
}

#[test]
fn genuine_same_height_and_later_certified_forks_never_replace_progress() {
    for comparison_height in [2, 3] {
        let mut fixture = Fixture::new();
        let initial = original(&fixture);
        let (receipt, mut comparison) = fixture.parent_receipt();
        if comparison_height == 3 {
            comparison = fixture.parent_receipt().1;
        }
        let mut fork = Fixture::new();
        let mut source = Source::default();
        if comparison_height == 3 {
            fork.parent_receipt();
            source.retain(&fork);
        }
        let mut header = fork.parent.next_header();
        header.creation_time_ms += 19;
        let block = fork.parent.block_with_submitted_work(header);
        fork.parent.certify(block);
        source.retain(&fork);
        let mut replay = ParentReplay::new(
            &fixture.identity,
            &initial,
            NonZeroU64::new(2).unwrap(),
            &comparison,
        )
        .unwrap();
        if comparison_height == 3 {
            replay.advance_page(&fixture.identity, &source).unwrap();
            replay.retain_carrier(&fixture.identity, receipt).unwrap();
        }
        let before = norito::encode_canonical(&replay).unwrap();
        assert!(replay.advance_page(&fixture.identity, &source).is_err());
        assert_eq!(before, norito::encode_canonical(&replay).unwrap());
        assert!(replay.completed(&fixture.identity).unwrap().is_none());
    }
}

#[test]
fn restore_rejects_inconsistent_milestones_foreign_checkpoints_and_carrier_substitution() {
    let mut fixture = Fixture::new();
    let initial = original(&fixture);
    let (receipt, comparison) = fixture.parent_receipt();
    let replay = ParentReplay::new(
        &fixture.identity,
        &initial,
        NonZeroU64::new(2).unwrap(),
        &comparison,
    )
    .unwrap();
    let mut malformed = replay.clone();
    malformed.comparison_verified = true;
    assert!(malformed.validate(&fixture.identity, &initial).is_err());
    let mut malformed = replay.clone();
    malformed.carrier_height = 1;
    assert!(malformed.validate(&fixture.identity, &initial).is_err());
    let mut malformed = replay.clone();
    malformed.progress = fixture.child.checkpoint().encode_canonical().unwrap();
    assert!(malformed.validate(&fixture.identity, &initial).is_err());
    let mut malformed = replay.clone();
    assert!(
        malformed
            .retain_carrier(&fixture.identity, receipt)
            .is_err()
    );
    assert!(
        ParentReplay::new(
            &fixture.identity,
            &comparison,
            NonZeroU64::new(3).unwrap(),
            &initial
        )
        .is_err()
    );
}

#[test]
fn one_turn_is_bounded_to_sixteen_successors_and_restart_does_not_repeat_verified_work() {
    let mut fixture = Fixture::new();
    let initial = original(&fixture);
    let mut source = Source::default();
    let mut last = None;
    for _ in 0..17 {
        last = Some(fixture.parent_receipt().0);
        source.retain(&fixture);
    }
    let comparison = original(&fixture);
    let mut replay = ParentReplay::new(
        &fixture.identity,
        &initial,
        NonZeroU64::new(18).unwrap(),
        &comparison,
    )
    .unwrap();
    replay.advance_page(&fixture.identity, &source).unwrap();
    assert_eq!(*source.reads.borrow(), (2..=17).collect::<Vec<_>>());
    assert!(replay.needs_carrier_proof().is_none());
    assert!(replay.completed(&fixture.identity).unwrap().is_none());
    let mut replay = reopened(&replay, &fixture, &initial);
    replay.advance_page(&fixture.identity, &source).unwrap();
    assert_eq!(*source.reads.borrow(), (2..=18).collect::<Vec<_>>());
    replay
        .retain_carrier(&fixture.identity, last.unwrap())
        .unwrap();
    assert!(replay.completed(&fixture.identity).unwrap().is_some());
}
