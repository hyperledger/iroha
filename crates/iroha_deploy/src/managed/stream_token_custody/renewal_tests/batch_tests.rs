//! Native renewal batches preserve fresh per-peer proof production and original admission.

use super::*;
use crate::verify::finality::{FinalityAttestation, FinalitySource};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::peer::PeerId;
use norito::core::DecodeBudgetContext;

fn peers(fixture: &Fixture) -> Vec<PeerId> {
    fixture
        .native
        .chain
        .validators()
        .iter()
        .rev()
        .map(|(peer, _)| peer.clone())
        .collect()
}

#[test]
fn native_renewal_batch_keeps_original_order_fresh_binding_and_per_peer_refusal() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(120_000);
    let trace = std::cell::RefCell::new(ObservationTrace::default());
    let source = NativeRenewalSource {
        native: &fixture.native,
        trace: Some(&trace),
        replay_challenge: None,
    };
    let selected = peers(&fixture);
    let challenge = [83; 32];
    let started = now_ms().unwrap();
    let reads = source.latest_attestations(&selected, &challenge);
    let finished = now_ms().unwrap();
    assert_eq!(reads.len(), selected.len());
    assert_eq!(trace.borrow().challenges, vec![challenge; selected.len()]);
    for (peer, actual) in selected.iter().zip(reads) {
        let FinalityAttestation::Raw(actual) = actual.unwrap() else {
            panic!("the native fixture must not claim SDK authentication provenance");
        };
        actual.verify().unwrap();
        assert_eq!(&actual.body.node_id, peer);
        assert_eq!(actual.body.challenge, challenge);
        assert_eq!(actual.body.network_id, fixture.native.chain.network_id());
        assert_eq!(
            actual.body.status.instance,
            fixture.native.chain.instance().0
        );
        assert_eq!(
            actual.body.status.applied_height,
            fixture.native.chain.height()
        );
        assert!((started..=finished).contains(&actual.body.observed_at_unix_ms));
        let expected = source.latest_attestation(peer, &challenge).unwrap();
        expected.attestation().verify().unwrap();
        // Each producer reads its real clock. All other signed fields match the serial call.
        let mut expected_body = expected.attestation().body.clone();
        expected_body.observed_at_unix_ms = actual.body.observed_at_unix_ms;
        assert_eq!(actual.body, expected_body);
    }

    let outsider = PeerId::new(
        KeyPair::from_seed(vec![0xe7; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    let mut with_outsider = selected.clone();
    with_outsider.insert(1, outsider);
    let next_challenge = [84; 32];
    let reads = source.latest_attestations(&with_outsider, &next_challenge);
    assert_eq!(reads.len(), with_outsider.len());
    for (index, (peer, result)) in with_outsider.iter().zip(reads).enumerate() {
        if index == 1 {
            assert_eq!(
                result.unwrap_err().to_string(),
                "peer is outside generated genesis"
            );
        } else {
            let actual = result.unwrap();
            actual.attestation().verify().unwrap();
            assert_eq!(&actual.attestation().body.node_id, peer);
            assert_eq!(actual.attestation().body.challenge, next_challenge);
        }
    }
    let (mut verifier, _) = fixture.current();
    let before = checkpoint_bytes(&verifier).unwrap();
    let replay = NativeRenewalSource {
        native: &fixture.native,
        trace: None,
        replay_challenge: Some(challenge),
    };
    assert!(verifier.observe(&replay, &next_challenge).is_err());
    assert_eq!(checkpoint_bytes(&verifier).unwrap(), before);
}

#[test]
fn native_renewal_batch_preserves_original_caller_decode_refusals_and_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(120_000);
    let trace = std::cell::RefCell::new(ObservationTrace::default());
    let source = NativeRenewalSource {
        native: &fixture.native,
        trace: Some(&trace),
        replay_challenge: None,
    };
    let selected = peers(&fixture);
    let challenge = [85; 32];
    for cap in [0, 1] {
        let limits = || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, cap, 64);
        let expected_budget = DecodeBudgetContext::new(limits());
        let expected = expected_budget.with(|| {
            selected
                .iter()
                .map(|peer| source.latest_attestation(peer, &challenge))
                .collect::<Vec<_>>()
        });
        trace.borrow_mut().challenges.clear();
        let actual_budget = DecodeBudgetContext::new(limits());
        let actual = actual_budget.with(|| source.latest_attestations(&selected, &challenge));
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.into_iter().zip(expected) {
            let actual = actual.unwrap_err();
            let expected = expected.unwrap_err();
            assert_eq!(actual.kind(), expected.kind());
            assert_eq!(actual.to_string(), expected.to_string());
        }
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
        assert_eq!(trace.borrow().challenges, vec![challenge; selected.len()]);
    }
    // Ending the refused owner permits the exact original source and a new challenge to retry.
    assert!(!norito::core::decode_limits_active());
    let retry = [86; 32];
    for (peer, result) in selected
        .iter()
        .zip(source.latest_attestations(&selected, &retry))
    {
        let actual = result.unwrap();
        actual.attestation().verify().unwrap();
        assert_eq!(&actual.attestation().body.node_id, peer);
        assert_eq!(actual.attestation().body.challenge, retry);
    }
}
