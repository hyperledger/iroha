//! Borrowed effects preserve exact original custody and canonical snapshot projections.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::sample_fast_pause;
use norito::codec::Encode;

fn pause(source: &SccpFastPauseV1) -> FastPauseDraft<'_> {
    FastPauseDraft {
        certificate_id: source.certificate_id,
        effect_hash: source.effect_hash,
        panel_id: source.panel_id,
        enacted_at: source.enacted_at,
        enacted_at_ms: source.enacted_at_ms,
        until_ms: source.until_ms,
        taira: source.taira,
        revisions: &source.revisions,
    }
}
fn panel<'a>(
    source: &SccpPausePanelV1,
    drawn: &'a [&'a AccountId],
    accepted: &'a [&'a AccountId],
) -> PausePanelDraft<'a> {
    PausePanelDraft {
        panel_seq: source.panel_seq,
        pulse_id: source.pulse_id,
        seated_height: source.seated_height,
        seated_at_ms: source.seated_at_ms,
        accept_until_ms: source.accept_until_ms,
        term_ends_at_ms: source.term_ends_at_ms,
        drawn,
        accepted,
        primary_id: source.primary_id,
        backup_id: source.backup_id,
    }
}
fn round<'a>(
    source: &SccpFastPauseRoundV1,
    endorsers: &'a [(&'a AccountId, SccpFastPauseEndorsementV1)],
) -> FastPauseRoundDraft<'a> {
    FastPauseRoundDraft {
        panel_id: source.panel_id,
        panel_seq: source.panel_seq,
        head: source.head,
        opened_at_ms: source.opened_at_ms,
        closes_at_ms: source.closes_at_ms,
        endorsers,
        certify_due: source.certify_due,
    }
}

#[test]
fn borrowed_effect_drafts_admit_exact_original_graphs_and_clones_share_custody() {
    macro_rules! check {
        ($dto:expr, $draft:expr, $owner:ty) => {{
            let draft = $draft;
            let bytes = <$owner>::draft_admission_demand(&draft).unwrap();
            assert_eq!(bytes, <$owner>::admission_demand($dto).unwrap());
            let empty = AllocationBudget::new(0);
            assert!(matches!(
                <$owner>::admit_draft(&draft, &empty),
                Err(PauseRecordError::Admission(_))
            ));
            assert_eq!(empty.reserved_bytes(), 0);
            let budget = AllocationBudget::new(bytes);
            let owner = <$owner>::admit_draft(&draft, &budget).unwrap();
            assert_eq!(budget.reserved_bytes(), bytes);
            assert_eq!(owner.encode(), $dto.encode());
            assert_eq!(
                norito::json::to_json(&owner).unwrap(),
                norito::json::to_json($dto).unwrap()
            );
            let copy = owner.clone();
            drop(owner);
            assert_eq!(budget.reserved_bytes(), bytes);
            drop(copy);
            assert_eq!(budget.reserved_bytes(), 0);
            let foreign = AllocationBudget::new(bytes);
            let mut prepaid = foreign.try_reserve_bytes(bytes).unwrap();
            assert!(matches!(
                <$owner>::admit_draft_prepaid(&draft, &budget, &mut prepaid),
                Err(PauseRecordError::Invalid("foreign original reservation"))
            ));
            assert_eq!(budget.reserved_bytes(), 0);
            assert_eq!(prepaid.remaining_bytes(), bytes);
        }};
    }
    let dto = sample_fast_pause(1);
    check!(&dto, pause(&dto), RetainedSccpFastPause);
    let dto = super::super::tests::panel();
    let drawn = dto.drawn.iter().collect::<Vec<_>>();
    let accepted = dto.accepted.iter().collect::<Vec<_>>();
    check!(&dto, panel(&dto, &drawn, &accepted), RetainedSccpPausePanel);
    let dto = super::super::tests::round();
    let endorsers = dto
        .endorsers
        .iter()
        .map(|(key, value)| (key, *value))
        .collect::<Vec<_>>();
    check!(&dto, round(&dto, &endorsers), RetainedSccpFastPauseRound);
}

#[test]
fn borrowed_drafts_refuse_noncanonical_inputs_before_charging() {
    let budget = AllocationBudget::new(1 << 20);
    let dto = super::super::tests::panel();
    let drawn = dto.drawn.iter().collect::<Vec<_>>();
    let mut accepted = dto.accepted.iter().collect::<Vec<_>>();
    accepted.push(accepted[0]);
    assert!(matches!(
        RetainedSccpPausePanel::admit_draft(&panel(&dto, &drawn, &accepted), &budget),
        Err(PauseRecordError::Invalid(_))
    ));
    let mut repeated = drawn.clone();
    repeated[1] = repeated[0];
    assert!(RetainedSccpPausePanel::admit_draft(&panel(&dto, &repeated, &[]), &budget).is_err());
    let too_many = [drawn[0]; SCCP_PAUSE_PANEL_MAX_DRAWN_V1 + 1];
    assert!(RetainedSccpPausePanel::admit_draft(&panel(&dto, &too_many, &[]), &budget).is_err());
    let dto = super::super::tests::round();
    let mut endorsers = dto
        .endorsers
        .iter()
        .map(|(key, value)| (key, *value))
        .collect::<Vec<_>>();
    endorsers.push(endorsers[0]);
    assert!(RetainedSccpFastPauseRound::admit_draft(&round(&dto, &endorsers), &budget).is_err());
    let too_many = [endorsers[0]; SCCP_PAUSE_PANEL_MAX_DRAWN_V1 + 1];
    assert!(RetainedSccpFastPauseRound::admit_draft(&round(&dto, &too_many), &budget).is_err());
    let dto = sample_fast_pause(1);
    let mut draft = pause(&dto);
    draft.revisions = &[2, 1];
    assert!(RetainedSccpFastPause::admit_draft(&draft, &budget).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn borrowed_round_retains_every_drawn_member_across_lazy_seat_changes() {
    let panel = super::super::tests::panel();
    let mut dto = super::super::tests::round();
    dto.endorsers = panel
        .drawn
        .iter()
        .enumerate()
        .map(|(index, account)| {
            (
                account.clone(),
                SccpFastPauseEndorsementV1 {
                    incident_digest: [u8::try_from(index).expect("fixture value fits u8") + 1; 32],
                    recorded_at_height: index as u64 + 1,
                },
            )
        })
        .collect();
    assert_eq!(dto.endorsers.len(), SCCP_PAUSE_PANEL_MAX_DRAWN_V1);
    let endorsers = dto
        .endorsers
        .iter()
        .map(|(key, value)| (key, *value))
        .collect::<Vec<_>>();
    let draft = round(&dto, &endorsers);
    let bytes = RetainedSccpFastPauseRound::draft_admission_demand(&draft).unwrap();
    let budget = AllocationBudget::new(bytes);
    let retained = RetainedSccpFastPauseRound::admit_draft(&draft, &budget).unwrap();
    assert_eq!(retained.encode(), dto.encode());
    assert_eq!(retained.endorsers.len(), 27);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn borrowed_draft_partial_account_and_shared_shell_unwind_refund_original_pool() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let dto = super::super::tests::panel();
    let drawn = dto.drawn.iter().collect::<Vec<_>>();
    let accepted = dto.accepted.iter().collect::<Vec<_>>();
    let draft = panel(&dto, &drawn, &accepted);
    let budget =
        AllocationBudget::new(RetainedSccpPausePanel::draft_admission_demand(&draft).unwrap());
    for stage in [
        ConstructionCheckpoint::NestedAccount,
        ConstructionCheckpoint::BeforeSharedShell,
    ] {
        CONSTRUCTION_UNWIND.with(|requested| requested.set(Some(stage)));
        assert!(
            catch_unwind(AssertUnwindSafe(|| RetainedSccpPausePanel::admit_draft(
                &draft, &budget
            )))
            .is_err()
        );
        assert_eq!(budget.reserved_bytes(), 0);
        let original = RetainedSccpPausePanel::admit_draft(&draft, &budget).unwrap();
        assert_eq!(original.encode(), dto.encode());
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
