//! Exact canonical projection and original-pool custody of every pause State graph.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{
    sample_fast_pause, sample_fast_pause_round, sample_pause_panel,
};
use norito::codec::{DecodeAll, Encode};

fn nested_account() -> AccountId {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            [101_u8, 102]
                .into_iter()
                .map(|seed| {
                    MultisigMember::new(
                        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                            .unwrap()
                            .public_key()
                            .clone(),
                        1,
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap(),
    )
}

pub(super) fn panel() -> SccpPausePanelV1 {
    let mut source = sample_pause_panel(1);
    source.accepted.remove(&source.drawn[0]);
    source.drawn[0] = nested_account();
    source.accepted.insert(source.drawn[0].clone());
    assert!(source.has_valid_shape());
    source
}

pub(super) fn round() -> SccpFastPauseRoundV1 {
    let mut source = sample_fast_pause_round(1);
    source.endorsers.insert(
        nested_account(),
        SccpFastPauseEndorsementV1 {
            incident_digest: [3; 32],
            recorded_at_height: 1,
        },
    );
    assert!(source.has_valid_shape());
    source
}

#[test]
fn pause_graphs_preserve_canonical_model_wire_and_json_without_map_nodes() {
    let budget = AllocationBudget::new(1024 * 1024);
    macro_rules! parity {
        ($source:expr, $owner:ty, $dto:ty) => {{
            let source = $source;
            let owner = <$owner>::admit(&source, &budget).unwrap();
            assert_eq!(owner.encode(), source.encode());
            assert_eq!(
                <$dto>::decode_all(&mut owner.encode().as_slice()).unwrap(),
                source
            );
            let encoded = norito::json::to_json(&owner).unwrap();
            assert_eq!(encoded, norito::json::to_json(&source).unwrap());
            assert_eq!(
                norito::json::to_json_bounded(&owner, encoded.len()).unwrap(),
                encoded
            );
            assert!(matches!(
                norito::json::to_json_bounded(&owner, encoded.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            ));
            assert_eq!(norito::json::from_json::<$dto>(&encoded).unwrap(), source);
        }};
    }
    parity!(sample_fast_pause(1), RetainedSccpFastPause, SccpFastPauseV1);
    parity!(panel(), RetainedSccpPausePanel, SccpPausePanelV1);
    let mut round = round();
    round.endorsers.clear();
    // Multiple differently ordered account encodings exercise the actual ordered-map kernel.
    let panel = panel();
    for (index, account) in panel.drawn.iter().enumerate() {
        round.endorsers.insert(
            account.clone(),
            SccpFastPauseEndorsementV1 {
                incident_digest: [u8::try_from(index).expect("fixture value fits u8") + 1; 32],
                recorded_at_height: index as u64 + 1,
            },
        );
    }
    parity!(round, RetainedSccpFastPauseRound, SccpFastPauseRoundV1);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_round_preserves_named_endorsements_and_original_height() {
    let mut source = round();
    let signer = nested_account();
    let original = SccpFastPauseEndorsementV1 {
        incident_digest: [0xa5; 32],
        recorded_at_height: u64::MAX,
    };
    source.endorsers.insert(signer.clone(), original);
    let bytes = RetainedSccpFastPauseRound::admission_demand(&source).unwrap();
    let budget = AllocationBudget::new(bytes);
    let owner = RetainedSccpFastPauseRound::admit(&source, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(
        owner
            .endorsers
            .iter()
            .find(|(account, _)| account == &signer)
            .unwrap()
            .1,
        original
    );
    let wire = owner.encode();
    let json = norito::json::to_json(&owner).unwrap();
    assert_eq!(wire, source.encode());
    assert_eq!(json, norito::json::to_json(&source).unwrap());
    source
        .endorsers
        .get_mut(&signer)
        .unwrap()
        .recorded_at_height = 7;
    source.endorsers.get_mut(&signer).unwrap().incident_digest = [0xb6; 32];
    let from_wire = SccpFastPauseRoundV1::decode_all(&mut wire.as_slice()).unwrap();
    let from_json = norito::json::from_json::<SccpFastPauseRoundV1>(&json).unwrap();
    assert_eq!(from_wire, from_json);
    assert_eq!(from_wire.endorsers[&signer], original);
    assert_ne!(from_wire.endorsers[&signer], source.endorsers[&signer]);
    assert_eq!(
        owner.encode(),
        wire,
        "the admitted graph cannot follow later DTO changes"
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pause_graph_clones_at_full_pool_preserve_original_backings_until_final_reader() {
    macro_rules! custody {
        ($source:expr, $owner:ty, $field:ident) => {{
            let source = $source;
            let bytes = <$owner>::admission_demand(&source).unwrap();
            let budget = AllocationBudget::new(bytes);
            let original = <$owner>::admit(&source, &budget).unwrap();
            assert_eq!(budget.reserved_bytes(), bytes);
            let reader = original.clone();
            assert!(ChargedShared::ptr_eq(&original.0, &reader.0));
            assert!(reader.0.belongs_to(&budget));
            assert_eq!(original.$field.as_ptr(), reader.$field.as_ptr());
            drop(original);
            assert_eq!(budget.reserved_bytes(), bytes);
            assert_eq!(reader.encode(), source.encode());
            drop(reader);
            assert_eq!(budget.reserved_bytes(), 0);
        }};
    }
    custody!(sample_fast_pause(1), RetainedSccpFastPause, revisions);
    custody!(panel(), RetainedSccpPausePanel, drawn);
    custody!(round(), RetainedSccpFastPauseRound, endorsers);
}

#[test]
fn pause_graph_refusal_is_atomic_and_prepaid_construction_requires_original_complete_credit() {
    macro_rules! admission {
        ($source:expr, $owner:ty) => {{
            let source = $source;
            let original_bytes = source.encode();
            let bytes = <$owner>::admission_demand(&source).unwrap();
            let budget = AllocationBudget::new(bytes - 1);
            assert!(matches!(
                <$owner>::admit(&source, &budget),
                Err(PauseRecordError::Admission(
                    AllocationRefusal::ExceedsLimit { .. }
                ))
            ));
            assert_eq!(budget.reserved_bytes(), 0);
            assert_eq!(source.encode(), original_bytes);
            budget.set_limit_bytes(bytes * 2);
            let other = AllocationBudget::new(bytes);
            let mut foreign = other.try_reserve_bytes(bytes).unwrap();
            assert!(matches!(
                <$owner>::admit_prepaid(&source, &budget, &mut foreign),
                Err(PauseRecordError::Invalid("foreign original reservation"))
            ));
            assert_eq!(foreign.remaining_bytes(), bytes);
            assert_eq!(budget.reserved_bytes(), 0);
            let mut short = budget.try_reserve_bytes(bytes - 1).unwrap();
            assert!(matches!(
                <$owner>::admit_prepaid(&source, &budget, &mut short),
                Err(PauseRecordError::Invalid("incomplete original reservation"))
            ));
            assert_eq!(short.remaining_bytes(), bytes - 1);
            drop(short);
            let mut aggregate = budget.try_reserve_bytes(bytes * 2).unwrap();
            let first = <$owner>::admit_prepaid(&source, &budget, &mut aggregate).unwrap();
            let second = <$owner>::admit_prepaid(&source, &budget, &mut aggregate).unwrap();
            assert_eq!(aggregate.remaining_bytes(), 0);
            drop(aggregate);
            assert_eq!(budget.reserved_bytes(), bytes * 2);
            drop(first);
            assert_eq!(budget.reserved_bytes(), bytes);
            drop(second);
            assert_eq!(budget.reserved_bytes(), 0);
        }};
    }
    admission!(sample_fast_pause(1), RetainedSccpFastPause);
    admission!(panel(), RetainedSccpPausePanel);
    admission!(round(), RetainedSccpFastPauseRound);
}

#[test]
fn invalid_pause_graphs_and_layout_overflow_fail_without_admission() {
    let budget = AllocationBudget::new(1024 * 1024);
    let mut pause = sample_fast_pause(1);
    pause.revisions.push(pause.revisions[0]);
    assert!(matches!(
        RetainedSccpFastPause::admit(&pause, &budget),
        Err(PauseRecordError::Invalid(_))
    ));
    let mut panel = panel();
    panel.drawn[1] = panel.drawn[0].clone();
    assert!(matches!(
        RetainedSccpPausePanel::admit(&panel, &budget),
        Err(PauseRecordError::Invalid(_))
    ));
    let mut round = round();
    round.endorsers.clear();
    assert!(matches!(
        RetainedSccpFastPauseRound::admit(&round, &budget),
        Err(PauseRecordError::Invalid(_))
    ));
    assert!(Demand::default().array::<AccountId>(usize::MAX).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn completed_pause_graph_unwind_preserves_other_readers_and_final_refund() {
    let budget = AllocationBudget::new(1024 * 1024);
    let first = RetainedSccpFastPause::admit(&sample_fast_pause(1), &budget).unwrap();
    let panel = RetainedSccpPausePanel::admit(&panel(), &budget).unwrap();
    let round = RetainedSccpFastPauseRound::admit(&round(), &budget).unwrap();
    let readers = (first.clone(), panel.clone(), round.clone());
    let bytes = budget.reserved_bytes();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _owners = (first, panel, round);
            panic!("completed owners unwind while current readers remain");
        }))
        .is_err()
    );
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(readers);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn partial_pause_nested_account_unwind_refunds_only_retired_graph() {
    macro_rules! check {
        ($source:expr, $owner:ty) => {{
            let source = $source;
            let budget = AllocationBudget::new(1024 * 1024);
            let original = <$owner>::admit(&source, &budget).unwrap();
            let bytes = budget.reserved_bytes();
            CONSTRUCTION_UNWIND
                .with(|requested| requested.set(Some(ConstructionCheckpoint::NestedAccount)));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _candidate = <$owner>::admit(&source, &budget).unwrap();
                }))
                .is_err()
            );
            assert!(CONSTRUCTION_UNWIND.with(|requested| requested.get().is_none()));
            assert_eq!(
                budget.reserved_bytes(),
                bytes,
                "all partial backings retired before credit refund"
            );
            assert_eq!(original.encode(), source.encode());
            drop(original);
            assert_eq!(budget.reserved_bytes(), 0);
        }};
    }
    check!(panel(), RetainedSccpPausePanel);
    check!(round(), RetainedSccpFastPauseRound);
}

#[test]
fn pause_unwind_before_shared_shell_preserves_original_readers_and_refunds_candidate() {
    macro_rules! check {
        ($source:expr, $owner:ty) => {{
            let source = $source;
            let budget = AllocationBudget::new(1024 * 1024);
            let original = <$owner>::admit(&source, &budget).unwrap();
            let bytes = budget.reserved_bytes();
            CONSTRUCTION_UNWIND
                .with(|requested| requested.set(Some(ConstructionCheckpoint::BeforeSharedShell)));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _candidate = <$owner>::admit(&source, &budget).unwrap();
                }))
                .is_err()
            );
            assert!(CONSTRUCTION_UNWIND.with(|requested| requested.get().is_none()));
            assert_eq!(budget.reserved_bytes(), bytes);
            assert_eq!(original.encode(), source.encode());
            drop(original);
            assert_eq!(budget.reserved_bytes(), 0);
        }};
    }
    check!(sample_fast_pause(1), RetainedSccpFastPause);
    check!(panel(), RetainedSccpPausePanel);
    check!(round(), RetainedSccpFastPauseRound);
}
