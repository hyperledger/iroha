//! Bounded scalar hold pages retained by their original request allocation through encoding.

use super::*;
use crate::smartcontracts::isi::sccp::{hold, reconciliation_store};
use iroha_sccp::api::{
    MAX_FORGERY_HOLD_PAGE, SccpForgeryHoldCursorV1, SccpForgeryHoldQuery,
    SccpForgeryHoldRevisionV1, SccpForgeryHoldViewV1,
};

/// Read a bounded page from one authenticated committed source.
/// # Errors
/// Preserves original source, allocation, deadline and cancellation refusals and rejects
/// invalid selectors before reserving row backing. No permanent proof history is copied.
pub fn forgery_hold(
    view: &impl StateReadOnly,
    query: SccpForgeryHoldQuery,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpForgeryHoldViewV1>> {
    validate_query(query)?;
    let source = source_identity(view, control)?;
    page(view.world(), source.timestamp_ms, query, budget, control)
}

fn validate_query(query: SccpForgeryHoldQuery) -> Result<()> {
    if !(1..=MAX_FORGERY_HOLD_PAGE).contains(&query.limit)
        || query
            .revision
            .is_some_and(|revision| revision == 0 || query.network.is_none())
        || query.network == Some(SccpNetworkV1::SoraTaira)
        || query.after.is_some_and(|cursor| {
            cursor.revision == 0 || cursor.network == SccpNetworkV1::SoraTaira
        })
    {
        return Err(SccpNativeReadError::Request("hold page selectors or limit"));
    }
    Ok(())
}

fn page(
    world: &impl WorldReadOnly,
    time: u64,
    query: SccpForgeryHoldQuery,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpForgeryHoldViewV1>> {
    deadline_check(control)?;
    let charge = budget.try_reserve_bytes(
        size_of::<SccpForgeryHoldViewV1>() + query.limit * size_of::<SccpForgeryHoldRevisionV1>(),
    )?;
    let mut revisions = Vec::new();
    revisions
        .try_reserve_exact(query.limit)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    let mut next = None;
    'routes: for (network, route) in store::routes::iter(world) {
        deadline_check(control)?;
        if query.network.is_some_and(|selected| selected != *network)
            || query.after.is_some_and(|cursor| *network < cursor.network)
        {
            continue;
        }
        let lower = match query.after.filter(|cursor| cursor.network == *network) {
            Some(cursor) => match cursor.revision.checked_add(1) {
                Some(value) => value,
                None => continue,
            },
            None => 1,
        };
        let start = query.revision.unwrap_or(lower).max(lower);
        let end = query.revision.unwrap_or(u32::MAX);
        if start > end {
            continue;
        }
        for (revision, record) in route.revisions.range(start..=end) {
            deadline_check(control)?;
            if revisions.len() == query.limit {
                next = revisions.last().map(|row: &SccpForgeryHoldRevisionV1| {
                    SccpForgeryHoldCursorV1 {
                        network: row.network,
                        revision: row.revision,
                    }
                });
                break 'routes;
            }
            revisions.push(SccpForgeryHoldRevisionV1 {
                network: *network,
                revision: *revision,
                forgery_floor: record.forgery_floor,
                held: hold::taira(world, *network, *revision, Some(time)),
                quarantine: record.quarantine,
                reconciliation: reconciliation_store::get(world, &(*network, *revision)).copied(),
            });
        }
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: SccpForgeryHoldViewV1 {
            max_generation: store::forgery_max_generation(world),
            revisions,
            next,
        },
        _charge: charge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{smartcontracts::isi::sccp::test_support::sample_route, state::World};
    use std::time::Duration;

    #[test]
    fn hold_page_retains_exact_bounded_rows_and_original_charge_through_encoding() {
        let world = World::new();
        let network = SccpNetworkV1::EthereumMainnet;
        let mut route = sample_route(network);
        let first = route.revisions[&1].clone();
        for revision in 2..=130 {
            let mut record = first.clone();
            record.revision = revision;
            route.revisions.insert(revision, record);
        }
        let mut block = world.block();
        block.sccp_routes.insert(network, route);
        let settled = iroha_data_model::sccp::reconciliation::SccpReconciliationStateV1 {
            opened_at_ms: 0,
            closes_at_ms: 10,
            forged_supply: 3,
            rho: Some(
                iroha_data_model::sccp::reconciliation::SccpReconciliationRatioV1 {
                    backing: 7,
                    denominator: 10,
                },
            ),
            settled_face: 5,
        };
        block
            .sccp_reconciliations
            .try_insert_admitted((network, 90), settled)
            .unwrap();
        block.commit();
        let stop = AtomicBool::new(false);
        let control = SccpNativeReadControl {
            deadline: Instant::now() + Duration::from_secs(3_600),
            stop: &stop,
        };
        let budget = AllocationBudget::new(64 << 10);
        let mut query = SccpForgeryHoldQuery::default();
        let one = page(&world.view(), 0, query, &budget, control).unwrap();
        assert_eq!(one.data().revisions.len(), 64);
        assert_eq!(one.data().revisions[0].revision, 1);
        assert_eq!(one.data().revisions[63].revision, 64);
        assert!(budget.reserved_bytes() >= 64 * size_of::<SccpForgeryHoldRevisionV1>());
        let json = norito::json::to_json(one.data()).unwrap();
        let decoded: SccpForgeryHoldViewV1 = norito::json::from_str(&json).unwrap();
        assert_eq!(&decoded, one.data());
        let bytes = norito::to_bytes(one.data()).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<SccpForgeryHoldViewV1>(&bytes).unwrap(),
            decoded
        );
        query.after = one.data().next;
        drop(one);
        assert_eq!(budget.reserved_bytes(), 0);
        let two = page(&world.view(), 0, query, &budget, control).unwrap();
        assert_eq!(two.data().revisions[0].revision, 65);
        query.after = two.data().next;
        drop(two);
        let three = page(&world.view(), 0, query, &budget, control).unwrap();
        assert_eq!(
            three
                .data()
                .revisions
                .iter()
                .map(|row| row.revision)
                .collect::<Vec<_>>(),
            vec![129, 130]
        );
        assert_eq!(three.data().next, None);
        drop(three);
        let exact = SccpForgeryHoldQuery {
            network: Some(network),
            revision: Some(90),
            ..Default::default()
        };
        let single = page(&world.view(), 0, exact, &budget, control).unwrap();
        assert_eq!(single.data().revisions.len(), 1);
        assert_eq!(single.data().revisions[0].revision, 90);
        assert_eq!(single.data().revisions[0].reconciliation, Some(settled));
        assert!(
            single.data().revisions[0].held,
            "other hold legs remain effective after reconciliation"
        );
        assert_eq!(single.data().next, None);
        drop(single);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(matches!(
            page(&world.view(), 0, query, &AllocationBudget::new(0), control),
            Err(SccpNativeReadError::Allocation(_))
        ));
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert!(matches!(
            page(&world.view(), 0, query, &budget, control),
            Err(SccpNativeReadError::Cancelled)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn hold_page_requires_valid_query_and_original_committed_source() {
        for query in [
            SccpForgeryHoldQuery {
                limit: 0,
                ..Default::default()
            },
            SccpForgeryHoldQuery {
                limit: 65,
                ..Default::default()
            },
            SccpForgeryHoldQuery {
                revision: Some(1),
                ..Default::default()
            },
            SccpForgeryHoldQuery {
                network: Some(SccpNetworkV1::SoraTaira),
                ..Default::default()
            },
        ] {
            assert!(validate_query(query).is_err());
        }
        let stop = AtomicBool::new(false);
        let control = SccpNativeReadControl {
            deadline: Instant::now() + Duration::from_secs(3_600),
            stop: &stop,
        };
        let budget = AllocationBudget::new(64 << 10);
        let chain = super::super::tests::active_chain();
        let result = forgery_hold(
            &chain.state().view(),
            SccpForgeryHoldQuery::default(),
            &budget,
            control,
        )
        .unwrap();
        assert!(result.data().revisions.is_empty());
        drop(result);
        assert_eq!(budget.reserved_bytes(), 0);
        let state = crate::smartcontracts::isi::sccp::test_support::blank_state();
        assert!(matches!(
            forgery_hold(
                &state.view(),
                SccpForgeryHoldQuery::default(),
                &budget,
                control
            ),
            Err(SccpNativeReadError::Unavailable(_))
        ));
        assert!(matches!(
            forgery_hold(
                &chain.state().view(),
                SccpForgeryHoldQuery::default(),
                &budget,
                SccpNativeReadControl {
                    deadline: Instant::now(),
                    ..control
                }
            ),
            Err(SccpNativeReadError::Deadline)
        ));
    }
}
