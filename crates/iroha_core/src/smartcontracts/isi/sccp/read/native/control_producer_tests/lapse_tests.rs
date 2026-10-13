//! Actual Global lapse consumers over the paid due-certificate fixture.
//!
//! The pause and route are pre-genesis component facts. The H60 Parliament confirmation,
//! native output, subsequent lapse/cancellation and publication all execute normally;
//! these controls do not qualify the missing panel or casting-open producers.

use super::*;
use crate::smartcontracts::isi::sccp::{hold, pause_record::RetainedSccpFastPause};
use iroha_data_model::events::{EventBox, data::DataEvent};

fn original_pause(chain: &CertifiedTestChain) -> RetainedSccpFastPause {
    let view = chain.state().view();
    let budget = chain.state().ivm_execution_budget();
    let bytes = budget.reserved_bytes();
    let retained = store::fast_pauses::get(view.world(), &ETH)
        .expect("original pre-genesis pause remains active through H61")
        .clone();
    assert_eq!(
        budget.reserved_bytes(),
        bytes,
        "reader retains the original charge without admission"
    );
    retained
}

fn work(chain: &CertifiedTestChain, time: u64) -> SignedTransaction {
    let key = KeyPair::from_seed(vec![0xce; 32], Algorithm::Ed25519);
    paid(
        chain,
        &key,
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "paid original lapse consumer".to_owned(),
        )
        .into()],
        time.checked_sub(1).unwrap(),
    )
}

// Compare the serialized event and all published fields after the storage-cause assertion.
fn lapse_events(events: &[EventBox]) -> Vec<norito::json::Value> {
    events
        .iter()
        .filter_map(|event| {
            let EventBox::Data(event) = event else {
                return None;
            };
            let DataEvent::Sccp(event) = event.as_ref() else {
                return None;
            };
            let value = norito::json::to_value(event).unwrap();
            (value.get("event").and_then(norito::json::Value::as_str) == Some("fast_pause_lapsed"))
                .then_some(value)
        })
        .collect()
}

fn assert_lapse_event(events: &[EventBox], original: &RetainedSccpFastPause) {
    let events = lapse_events(events);
    assert_eq!(
        events.len(),
        1,
        "one event for the exact expired original pause"
    );
    let payload = events[0].get("payload").unwrap();
    assert_eq!(
        payload.get("network"),
        Some(&norito::json::to_value(&ETH).unwrap())
    );
    assert_eq!(
        payload.get("certificate_id"),
        Some(&norito::json::to_value(&original.certificate_id).unwrap())
    );
    assert_eq!(
        payload.get("until_ms"),
        Some(&norito::json::to_value(&original.until_ms).unwrap())
    );
}

fn governance_heads(
    world: &(impl crate::state::WorldReadOnly + ?Sized),
) -> Vec<(SccpGovernanceSubjectV1, u64)> {
    store::governance_revisions::iter(world)
        .map(|(subject, revision)| (*subject, *revision))
        .collect()
}

fn assert_confirmation_unchanged(
    chain: &CertifiedTestChain,
    row: &iroha_data_model::sccp::control::SccpControlRecordV1,
    heads: &[(SccpGovernanceSubjectV1, u64)],
    height: u64,
) {
    let view = chain.state().view();
    let world = view.world();
    assert_eq!(store::control_messages::get(world, &(ETH, 1, 1)), Some(row));
    assert_eq!(store::control_messages::len(world), 1);
    assert_eq!(governance_heads(world).as_slice(), heads);
    let revision = &store::routes::get(world, &ETH).unwrap().revisions[&1];
    assert!(
        revision.destination_paused,
        "actual Parliament confirmation survives lapse"
    );
    assert_eq!(revision.next_control_nonce, 2);
    assert_eq!(revision.activation, SccpRouteActivationV1::Bidirectional);
    assert!(
        !store::block_commitments::contains(world, &height),
        "lapse creates no SCCP block commitment"
    );
    assert_eq!(
        store::block_leaves::range(world, (height, 0)..=(height, u32::MAX)).count(),
        0
    );
    assert_eq!(store::outbound_messages::len(world), 4);
}

#[test]
fn native_fast_pause_lapse_uses_exact_time_and_preserves_parliament_confirmation() {
    let (mut chain, _) = control_chain(false);
    let original = original_pause(&chain);
    let (row, heads) = {
        let view = chain.state().view();
        (
            *store::control_messages::get(view.world(), &(ETH, 1, 1)).unwrap(),
            governance_heads(view.world()),
        )
    };
    chain.take_events().unwrap();
    let before = original.until_ms - 1_000;
    let tx = work(&chain, before);
    assert_eq!(chain.commit_at(before, vec![tx]), [true]);
    assert_eq!(
        chain.committed(62).block().header().creation_time_ms,
        before
    );
    {
        let view = chain.state().view();
        let retained = store::fast_pauses::get(view.world(), &ETH).unwrap();
        assert!(
            std::ptr::eq(&**retained, &*original),
            "same original funded graph before expiry"
        );
        assert!(hold::fast_taira(view.world(), ETH, Some(before)));
        assert!(
            !hold::fast_taira(view.world(), ETH, Some(original.until_ms)),
            "hold ends at expiry without requiring cleanup"
        );
    }
    assert!(lapse_events(&chain.take_events().unwrap()).is_empty());
    let tx = work(&chain, original.until_ms);
    assert_eq!(chain.commit_at(original.until_ms, vec![tx]), [true]);
    assert_eq!(
        chain.committed(63).block().header().creation_time_ms,
        original.until_ms
    );
    assert!(
        !store::fast_pauses::contains(chain.state().view().world(), &ETH),
        "the first native block at expiry must remove the original fast-pause record"
    );
    assert_confirmation_unchanged(&chain, &row, &heads, 63);
    assert_lapse_event(&chain.take_events().unwrap(), &original);
    assert!(
        original.taira && !original.revisions.is_empty(),
        "retained reader still owns the original immutable graph"
    );
    let time = original.until_ms + 1_000;
    let tx = work(&chain, time);
    assert_eq!(chain.commit_at(time, vec![tx]), [true]);
    assert_confirmation_unchanged(&chain, &row, &heads, 64);
    assert!(
        lapse_events(&chain.take_events().unwrap()).is_empty(),
        "completed cleanup cannot repeat its event"
    );
}

#[test]
fn native_fast_pause_lapse_cancellation_keeps_original_record_and_retries_once() {
    let (mut chain, _) = control_chain(false);
    let original = original_pause(&chain);
    let tx = work(&chain, original.until_ms);
    let proposal = chain.proposal(Some(original.until_ms), vec![tx]);
    assert_eq!(proposal.header().creation_time_ms, original.until_ms);
    let original_hash = proposal.hash();
    chain.take_events().unwrap();
    {
        let mut pending = chain
            .begin_proposal(proposal.clone(), Default::default())
            .unwrap();
        let removed = pending
            .inspect(|pending| !store::fast_pauses::contains(&pending.state.world, &ETH))
            .unwrap();
        assert!(
            removed,
            "the original native execution must stage lapse before publication"
        );
        // Dropping this genuine Worker owner discards its original overlay and events.
    }
    assert_eq!(chain.height(), 61);
    {
        let view = chain.state().view();
        let retained = store::fast_pauses::get(view.world(), &ETH).unwrap();
        assert!(
            std::ptr::eq(&**retained, &*original),
            "discard retains original pause backing"
        );
    }
    assert!(
        lapse_events(&chain.take_events().unwrap()).is_empty(),
        "discard publishes no lapse event"
    );
    assert_eq!(proposal.hash(), original_hash);
    {
        let mut retry = chain.begin_proposal(proposal, Default::default()).unwrap();
        let first = retry
            .publish(crate::sumeragi::test_chain::Signers::Quorum)
            .unwrap();
        let again = retry
            .publish(crate::sumeragi::test_chain::Signers::Quorum)
            .unwrap();
        assert_eq!(first.block().hash(), original_hash);
        assert_eq!(again.result(), first.result());
    }
    assert!(!store::fast_pauses::contains(
        chain.state().view().world(),
        &ETH
    ));
    assert_lapse_event(&chain.take_events().unwrap(), &original);
}

#[test]
fn direct_state_block_without_original_native_scope_cannot_lapse_pause() {
    let (chain, _) = control_chain(false);
    let original = original_pause(&chain);
    let tx = work(&chain, original.until_ms);
    let proposal = chain.proposal(Some(original.until_ms), vec![tx]);
    let block = chain.state().try_block(proposal.header()).unwrap();
    let retained = store::fast_pauses::get(&block.world, &ETH).unwrap();
    assert!(
        std::ptr::eq(&**retained, &*original),
        "a header alone grants no Global lifecycle authority"
    );
    drop(block);
    assert!(store::fast_pauses::contains(
        chain.state().view().world(),
        &ETH
    ));
}
