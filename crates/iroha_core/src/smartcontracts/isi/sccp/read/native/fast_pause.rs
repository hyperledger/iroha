//! Original funded pause graphs, borrowed seats and completed anchor observations.

use super::*;
use crate::smartcontracts::isi::sccp::{
    fast_pause, forgery,
    pause_record::{RetainedSccpFastPause, RetainedSccpFastPauseRound, RetainedSccpPausePanel},
};
use iroha_data_model::{account::AccountId, sccp::fast_pause::SccpPanelRoleV1};
use iroha_sccp::{
    api::{SccpAnchorWitnessBundleV1, SccpFastPauseSuspendedViewV1, SccpFastPauseViewV1},
    v1::evidence::anchor_chunk_position,
};
use norito::{
    core::{Encoder, PayloadRef, SerializePayload},
    json::{self, JsonSerialize},
};

const NETWORKS: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct Round {
    network: SccpNetworkV1,
    role: SccpPanelRoleV1,
    round: RetainedSccpFastPauseRound,
}
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct Active {
    network: SccpNetworkV1,
    pause: RetainedSccpFastPause,
}

/// A finite response retaining the original charged panel and round account graphs.
/// There is no decoded DATA constructor for this source owner.
pub struct RetainedFastPauseView {
    panel: Option<RetainedSccpPausePanel>,
    seats: Option<([usize; 18], usize)>,
    rounds: Vec<Round>,
    active: Vec<Active>,
    suspended: Vec<SccpFastPauseSuspendedViewV1>,
}

struct Accounts<'a> {
    panel: &'a RetainedSccpPausePanel,
    indices: &'a [usize],
}
impl SerializePayload for Accounts<'_> {
    fn serialize(&self, out: &mut Encoder<'_>) -> core::result::Result<(), norito::Error> {
        norito::core::write_element_sequence::<AccountId, _>(
            out,
            self.indices.iter().map(|index| &self.panel.drawn[*index]),
        )
    }
}
impl JsonSerialize for Accounts<'_> {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (position, index) in self.indices.iter().enumerate() {
            if position != 0 {
                out.push(',');
            }
            self.panel.drawn[*index].json_serialize(out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> core::result::Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (position, index) in self.indices.iter().enumerate() {
                if position != 0 {
                    out.push(',')?;
                }
                self.panel.drawn[*index].json_serialize_to(out)?;
            }
            out.push(']')
        })();
        out.end_container();
        result
    }
}
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct Seats<'a> {
    primary: Accounts<'a>,
    backup: Accounts<'a>,
}
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct View<'a> {
    panel: PayloadRef<'a, Option<RetainedSccpPausePanel>>,
    seats: Option<Seats<'a>>,
    eligibility_available: bool,
    rounds: PayloadRef<'a, Vec<Round>>,
    active: PayloadRef<'a, Vec<Active>>,
    suspended: PayloadRef<'a, Vec<SccpFastPauseSuspendedViewV1>>,
}
impl RetainedFastPauseView {
    fn view(&self) -> View<'_> {
        let seats = self
            .seats
            .as_ref()
            .zip(self.panel.as_ref())
            .map(|((indices, k), panel)| Seats {
                primary: Accounts {
                    panel,
                    indices: &indices[..*k],
                },
                backup: Accounts {
                    panel,
                    indices: &indices[*k..2 * k],
                },
            });
        View {
            panel: PayloadRef(&self.panel),
            eligibility_available: seats.is_some(),
            seats,
            rounds: PayloadRef(&self.rounds),
            active: PayloadRef(&self.active),
            suspended: PayloadRef(&self.suspended),
        }
    }
}
impl norito::NoritoSchema for RetainedFastPauseView {
    fn nominal_name() -> String {
        <SccpFastPauseViewV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SccpFastPauseViewV1 as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedFastPauseView {
    fn serialize(&self, out: &mut Encoder<'_>) -> core::result::Result<(), norito::Error> {
        self.view().serialize(out)
    }
}
impl JsonSerialize for RetainedFastPauseView {
    fn json_serialize(&self, out: &mut String) {
        self.view().json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> core::result::Result<(), json::BoundedJsonError> {
        self.view().json_serialize_to(out)
    }
}

/// Read bounded pause state with original graph custody and explicit unavailable seats.
/// # Errors
/// Refuses original-source, deadline, cancellation and original response-budget failures.
pub fn fast_pause(
    view: &impl StateReadOnly,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<RetainedFastPauseView>> {
    let source = source_identity(view, control)?;
    pause_page(view.world(), source.timestamp_ms, budget, control)
}

fn pause_page(
    world: &impl WorldReadOnly,
    time: u64,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<RetainedFastPauseView>> {
    deadline_check(control)?;
    let charge = budget.try_reserve_bytes(
        size_of::<RetainedFastPauseView>()
            + 6 * size_of::<Round>()
            + 3 * size_of::<Active>()
            + 3 * size_of::<SccpFastPauseSuspendedViewV1>(),
    )?;
    let mut response = RetainedFastPauseView {
        panel: store::pause_panel::get(world).clone(),
        seats: None,
        rounds: Vec::new(),
        active: Vec::new(),
        suspended: Vec::new(),
    };
    response
        .rounds
        .try_reserve_exact(6)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    response
        .active
        .try_reserve_exact(3)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    response
        .suspended
        .try_reserve_exact(3)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    // The external Parliament owns eligibility. An unavailable observation retains raw
    // original records, with None seats; it never invents an eligible empty committee.
    if let Ok(Some(seats)) = fast_pause::current_seats(world, time) {
        if response.panel.as_ref().is_none_or(|panel| {
            !core::ptr::eq(
                core::ptr::from_ref(&**panel),
                core::ptr::from_ref(&**seats.panel),
            )
        }) {
            return Err(SccpNativeReadError::Unavailable(
                "seat projection changed original panel",
            ));
        }
        response.seats = Some((seats.indices, seats.seats_per_panel));
    }
    for network in NETWORKS {
        deadline_check(control)?;
        for role in [SccpPanelRoleV1::Primary, SccpPanelRoleV1::Backup] {
            if let Some(round) = store::fast_pause_rounds::get(world, &(network, role)) {
                response.rounds.push(Round {
                    network,
                    role,
                    round: round.clone(),
                });
            }
        }
        if let Some(pause) = store::fast_pauses::get(world, &network) {
            response.active.push(Active {
                network,
                pause: pause.clone(),
            });
        }
        if let Some(until_ms) = store::fast_pause_suspended_until_ms::get(world, &network) {
            response.suspended.push(SccpFastPauseSuspendedViewV1 {
                network,
                until_ms: *until_ms,
            });
        }
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: response,
        _charge: charge,
    })
}

/// Read an anchor witness from original Kura when the requested chunk is completed.
/// # Errors
/// Refuses out-of-view heights, missing retained roots and original source/resource failures.
pub fn anchor_witness(
    view: &StateView<'_>,
    height: NonZeroU64,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpAnchorWitnessBundleV1>> {
    let source = source_identity(view, control)?;
    if height.get() > source.height {
        return Err(SccpNativeReadError::Request(
            "anchor height is outside committed view",
        ));
    }
    let (chunk, _) = anchor_chunk_position(height.get())
        .ok_or(SccpNativeReadError::Request("zero anchor height"))?;
    let (open, _) = anchor_chunk_position(source.height)
        .ok_or(SccpNativeReadError::Unavailable("zero native tip"))?;
    let charge = budget.try_reserve_bytes(size_of::<SccpAnchorWitnessBundleV1>())?;
    let witness = if chunk == open {
        None
    } else {
        Some(
            forgery::keeper::anchor_witness(view, height.get(), budget, control).map_err(
                |error| match error {
                    forgery::ForgeryVerificationError::EvidenceExpired => {
                        SccpNativeReadError::Pruned("completed anchor root")
                    }
                    forgery::ForgeryVerificationError::Cancelled => SccpNativeReadError::Cancelled,
                    forgery::ForgeryVerificationError::Deadline => SccpNativeReadError::Deadline,
                    forgery::ForgeryVerificationError::Allocation(error) => {
                        SccpNativeReadError::Allocation(error)
                    }
                    _ => SccpNativeReadError::Unavailable(
                        "original completed anchor witness unavailable",
                    ),
                },
            )?,
        )
    };
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: SccpAnchorWitnessBundleV1 {
            height: height.get(),
            chunk,
            witness,
        },
        _charge: charge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::AtomicBool, time::Duration};

    #[test]
    fn pause_view_retains_original_nonempty_graphs_and_matches_public_codecs() {
        use crate::smartcontracts::isi::sccp::test_support::{
            blank_state, header, sample_fast_pause, sample_fast_pause_round, sample_pause_panel,
        };
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut tx = block.transaction();
        let graph_budget = tx.sccp_evidence_preparation_budget();
        let panel = RetainedSccpPausePanel::admit(&sample_pause_panel(1), graph_budget).unwrap();
        let round =
            RetainedSccpFastPauseRound::admit(&sample_fast_pause_round(1), graph_budget).unwrap();
        let pause = RetainedSccpFastPause::admit(&sample_fast_pause(1), graph_budget).unwrap();
        store::pause_panel::set(&mut tx, Some(panel.clone()));
        for network in NETWORKS {
            for role in [SccpPanelRoleV1::Primary, SccpPanelRoleV1::Backup] {
                store::fast_pause_rounds::insert(&mut tx, (network, role), round.clone()).unwrap();
            }
            store::fast_pauses::insert(&mut tx, network, pause.clone()).unwrap();
            store::fast_pause_suspended_until_ms::insert(&mut tx, network, 999).unwrap();
        }
        let stop = AtomicBool::new(false);
        let control = SccpNativeReadControl {
            deadline: Instant::now() + Duration::from_secs(1),
            stop: &stop,
        };
        let budget = AllocationBudget::new(4096);
        let original_bytes = tx.sccp_evidence_preparation_budget().reserved_bytes();
        let response = pause_page(&*tx.world, 10_000, &budget, control).unwrap();
        assert_eq!(
            tx.sccp_evidence_preparation_budget().reserved_bytes(),
            original_bytes
        );
        assert!(core::ptr::eq(
            &raw const **response.data.panel.as_ref().unwrap(),
            &raw const *panel
        ));
        assert!(core::ptr::eq(
            &raw const *response.data.rounds[0].round,
            &raw const *round
        ));
        assert!(core::ptr::eq(
            &raw const *response.data.active[0].pause,
            &raw const *pause
        ));
        drop(tx);
        drop(block);
        let wire: SccpFastPauseViewV1 =
            norito::json::from_json(&norito::json::to_json(response.data()).unwrap()).unwrap();
        assert_eq!(wire.panel, Some(sample_pause_panel(1)));
        assert_eq!(wire.rounds.len(), 6);
        assert_eq!(wire.active.len(), 3);
        assert_eq!(wire.suspended.len(), 3);
        assert_eq!(wire.rounds[0].round, sample_fast_pause_round(1));
        assert_eq!(wire.active[0].pause, sample_fast_pause(1));
        assert!(wire.seats.is_none() && !wire.eligibility_available);
        assert_eq!(
            norito::decode_from_bytes::<SccpFastPauseViewV1>(
                &norito::to_bytes(response.data()).unwrap()
            )
            .unwrap(),
            wire
        );
        assert!(budget.reserved_bytes() > 0);
        drop(response);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn pause_view_keeps_unavailable_eligibility_explicit_and_original_budget_funded() {
        let state = crate::smartcontracts::isi::sccp::test_support::blank_state();
        let view = state.view();
        let stop = AtomicBool::new(false);
        let control = SccpNativeReadControl {
            deadline: Instant::now() + Duration::from_secs(1),
            stop: &stop,
        };
        let budget = AllocationBudget::new(4096);
        let response = pause_page(view.world(), 1, &budget, control).unwrap();
        let json = norito::json::to_json(response.data()).unwrap();
        let wire: SccpFastPauseViewV1 = norito::json::from_json(&json).unwrap();
        assert!(!wire.eligibility_available && wire.seats.is_none() && wire.panel.is_none());
        assert_eq!(
            norito::decode_from_bytes::<SccpFastPauseViewV1>(
                &norito::to_bytes(response.data()).unwrap()
            )
            .unwrap(),
            wire
        );
        assert!(matches!(
            pause_page(view.world(), 1, &AllocationBudget::new(0), control),
            Err(SccpNativeReadError::Allocation(_))
        ));
        stop.store(true, Ordering::Release);
        assert!(matches!(
            pause_page(view.world(), 1, &budget, control),
            Err(SccpNativeReadError::Cancelled)
        ));
        assert!(matches!(
            anchor_witness(&view, NonZeroU64::new(1).unwrap(), &budget, control),
            Err(SccpNativeReadError::Cancelled)
        ));
    }
}
