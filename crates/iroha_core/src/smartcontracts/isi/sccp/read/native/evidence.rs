//! Bounded original evidence views without copying the retained offender graph.

use super::*;
use crate::state::RetainedEvidenceRecord;
use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::{EvidencePenaltyStatus, EvidenceScope, RecordedEvidenceV1},
    sccp::native::{SccpForgeryOffenderV1, SccpForgeryRuleV1},
};
use iroha_sccp::api;
use mv::storage::StorageReadOnly;
use norito::core::PayloadRef;
use std::ops::Bound;

/// One original evidence status borrowing the original admitted member graph.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct Status<'a> {
    evidence_id: [u8; 32],
    generation: u64,
    height: u64,
    rule: SccpForgeryRuleV1,
    offenders: PayloadRef<'a, Vec<SccpForgeryOffenderV1>>,
    penalty_status: EvidencePenaltyStatus,
    recorded_at_height: u64,
}
/// One request-funded bounded vector of original status borrows.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct Page<'a> {
    records: Vec<Status<'a>>,
    next_after: Option<[u8; 32]>,
}
macro_rules! schema {
    ($view:ty, $wire:ty) => {
        impl norito::NoritoSchema for $view {
            fn nominal_name() -> String {
                <$wire as norito::NoritoSchema>::nominal_name()
            }
            fn frame_name() -> String {
                <$wire as norito::NoritoSchema>::frame_name()
            }
        }
    };
}
schema!(Status<'_>, api::SccpForgeryEvidenceStatusV1);
schema!(Page<'_>, api::SccpForgeryEvidencePageV1);

fn status<'a>(key: &Hash, retained: &'a RetainedEvidenceRecord) -> Result<Option<Status<'a>>> {
    let RecordedEvidenceV1::SccpForgery(record) = &retained.evidence else {
        return Ok(None);
    };
    let evidence_id = retained
        .sccp_evidence_id()
        .ok_or(SccpNativeReadError::Invalid("retained evidence identity"))?;
    if *key != Hash::prehashed(evidence_id)
        || retained.attribution.scope
            != (EvidenceScope::SccpGeneration {
                generation: record.generation,
            })
        || retained.recorded_at_height == 0
    {
        return Err(SccpNativeReadError::Invalid(
            "retained evidence coordinates",
        ));
    }
    let header = SccpFinalityHeaderV1::parse(&record.evidence.header)
        .map_err(|_| SccpNativeReadError::Invalid("retained evidence header"))?;
    if header.generation() != record.generation {
        return Err(SccpNativeReadError::Invalid("retained evidence generation"));
    }
    Ok(Some(Status {
        evidence_id,
        generation: record.generation,
        height: header.height(),
        rule: record.rule,
        offenders: PayloadRef(&record.offenders),
        penalty_status: retained.penalty_status,
        recorded_at_height: retained.recorded_at_height,
    }))
}

/// Read one exact committed evidence id; Hash-marker aliases never select a different report.
/// # Errors
/// Preserves original request capacity, stop, deadline, absence and malformed-source refusal.
pub fn detail<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    id: [u8; 32],
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Status<'a>>> {
    deadline_check(control)?;
    let charge = budget.try_reserve_bytes(size_of::<Status<'_>>())?;
    let key = Hash::prehashed(id);
    let record = view
        .world()
        .consensus_evidence()
        .get(&key)
        .ok_or(SccpNativeReadError::NotFound("forgery evidence"))?;
    let data = status(&key, record)?
        .filter(|row| row.evidence_id == id)
        .ok_or(SccpNativeReadError::NotFound("forgery evidence"))?;
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Scan the original ordered evidence owner with an exclusive cursor and a funded row bound.
/// # Errors
/// Rejects page bounds outside 1..=64 and preserves original resource/source refusal.
pub fn page<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    after: Option<[u8; 32]>,
    limit: usize,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Page<'a>>> {
    deadline_check(control)?;
    if !(1..=api::MAX_EVIDENCE_PAGE).contains(&limit) {
        return Err(SccpNativeReadError::Request("evidence page limit"));
    }
    let charge =
        budget.try_reserve_bytes(size_of::<Page<'_>>() + limit * size_of::<Status<'_>>())?;
    let mut data = Page {
        records: Vec::new(),
        next_after: None,
    };
    data.records
        .try_reserve_exact(limit)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    let start = after.map_or(Bound::Unbounded, |id| Bound::Excluded(Hash::prehashed(id)));
    for (key, record) in view
        .world()
        .consensus_evidence()
        .range((start, Bound::Unbounded))
    {
        deadline_check(control)?;
        let Some(row) = status(key, record)? else {
            continue;
        };
        if data.records.len() == limit {
            data.next_after = data.records.last().map(|last| last.evidence_id);
            break;
        }
        data.records.push(row);
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::forgery::tests::{
            active_member_chain_with_penalty_delay, future, resign,
        },
        sumeragi::test_chain::CertifiedTestChain,
    };
    use iroha_data_model::isi::InstructionBox;
    use iroha_sccp::v1::finality::QcFixedV1;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn recorded() -> CertifiedTestChain {
        let (mut chain, keys, signer) = active_member_chain_with_penalty_delay(20);
        for signers in [0b0111, 0b1110] {
            let mut evidence = future(&chain, &keys);
            let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
            qc.signers = signers;
            evidence.qc = qc.encode();
            resign(&mut evidence, &keys, chain.instance());
            let time = chain
                .state()
                .view()
                .native_execution_tip()
                .unwrap()
                .creation_time_ms()
                + 1;
            let transaction = chain.sign(&signer, [InstructionBox::from(evidence)], time);
            assert_eq!(chain.commit(vec![transaction]), [true]);
        }
        chain
    }

    #[test]
    fn original_evidence_pages_keep_attribution_custody_wire_parity_and_exact_cursor() {
        let chain = recorded();
        let view = chain.state().view();
        let budget = AllocationBudget::new(1 << 20);
        let stop = AtomicBool::new(false);
        let control = super::super::tests::control(&stop);
        let first = page(&view, None, 1, &budget, control).unwrap();
        assert_eq!(first.data.records.len(), 1);
        let cursor = first
            .data
            .next_after
            .expect("second genuine report remains");
        assert_eq!(cursor, first.data.records[0].evidence_id);
        let second = page(&view, Some(cursor), 1, &budget, control).unwrap();
        assert_eq!(second.data.records.len(), 1);
        assert_eq!(second.data.next_after, None);
        assert_ne!(second.data.records[0].evidence_id, cursor);
        let mut originals = Vec::new();
        for row in first.data.records.iter().chain(&second.data.records) {
            let retained = view
                .world()
                .consensus_evidence()
                .get(&Hash::prehashed(row.evidence_id))
                .unwrap();
            let RecordedEvidenceV1::SccpForgery(record) = &retained.evidence else {
                panic!("original SCCP record")
            };
            assert!(
                std::ptr::eq(row.offenders.0, &raw const record.offenders),
                "response borrows the original charged member graph"
            );
            let original = api::SccpForgeryEvidenceStatusV1 {
                evidence_id: row.evidence_id,
                generation: record.generation,
                height: SccpFinalityHeaderV1::parse(&record.evidence.header)
                    .unwrap()
                    .height(),
                rule: record.rule,
                offenders: record.offenders.clone(),
                penalty_status: retained.penalty_status,
                recorded_at_height: retained.recorded_at_height,
            };
            assert_eq!(
                norito::json::to_json(row).unwrap(),
                norito::json::to_json(&original).unwrap()
            );
            assert_eq!(
                norito::to_bytes(row).unwrap(),
                norito::to_bytes(&original).unwrap()
            );
            let single = detail(&view, row.evidence_id, &budget, control).unwrap();
            assert_eq!(single.data.recorded_at_height, row.recorded_at_height);
            let mut alias = row.evidence_id;
            alias[31] ^= 1;
            assert!(
                matches!(
                    detail(&view, alias, &budget, control),
                    Err(SccpNativeReadError::NotFound(_))
                ),
                "Hash marker is not an evidence identity alias"
            );
            originals.push(original);
        }
        let page_wire = api::SccpForgeryEvidencePageV1 {
            records: originals[..1].to_vec(),
            next_after: Some(cursor),
        };
        assert_eq!(
            norito::to_bytes(first.data()).unwrap(),
            norito::to_bytes(&page_wire).unwrap()
        );
        assert!(budget.reserved_bytes() > 0);
        drop(first);
        drop(second);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn evidence_capacity_and_stop_refuse_before_new_response_graph_and_retry_same_source() {
        let chain = recorded();
        let view = chain.state().view();
        let stop = AtomicBool::new(false);
        let control = super::super::tests::control(&stop);
        let demand = size_of::<Page<'_>>() + size_of::<Status<'_>>();
        let budget = AllocationBudget::new(demand);
        let occupied = budget.try_reserve_bytes(demand).unwrap();
        assert!(matches!(
            page(&view, None, 1, &budget, control),
            Err(SccpNativeReadError::Allocation(_))
        ));
        assert_eq!(budget.reserved_bytes(), demand);
        drop(occupied);
        let original = page(&view, None, 1, &budget, control).unwrap();
        assert_eq!(original.data.records.len(), 1);
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        for limit in [0, api::MAX_EVIDENCE_PAGE + 1] {
            assert!(matches!(
                page(&view, None, limit, &budget, control),
                Err(SccpNativeReadError::Request(_))
            ));
        }
        stop.store(true, Ordering::Release);
        assert!(matches!(
            page(&view, None, 1, &budget, control),
            Err(SccpNativeReadError::Cancelled)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
