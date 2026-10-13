//! G0 consumes only the existing authenticated pre-boundary pulse and original parent electorate.
use super::*;
use crate::state::{StateBlock, StateBlockStartError};
use iroha_crypto::Hash;
use iroha_data_model::sccp::events::{
    SccpPausePanelSeatedV1, SccpPausePanelUnavailableReasonV1, SccpPausePanelUnavailableV1,
};

/// One optional draw at this native pulse height; never registers a pulse or carries deferred work.
pub(crate) fn at_boundary<E: std::fmt::Debug>(
    state: &mut StateBlock<'_>,
) -> Result<(), StateBlockStartError<E>> {
    let Some(parameters) = *store::parameters::get(&state.world) else {
        return Ok(());
    };
    let time = state._curr_block.creation_time_ms;
    if store::pause_panel::get(&state.world)
        .as_ref()
        .is_some_and(|panel| time < panel.term_ends_at_ms)
    {
        return Ok(());
    }
    let Some(pulse) = state.sumeragi_schedule.original_native_pulse() else {
        return Ok(());
    };
    let sequence = store::pause_panel::get(&state.world)
        .as_ref()
        .map_or(Some(1), |panel| panel.panel_seq.checked_add(1))
        .ok_or_else(|| StateBlockStartError::Policy("SCCP panel sequence exhausted".into()))?;
    let seed = *Hash::new_from_chunks(&[
        b"sccp/pause-panel/v1",
        state.network_id().as_bytes(),
        &pulse.pulse_id,
        &sequence.to_be_bytes(),
    ])
    .as_ref();
    let k = parameters.fast_pause_panel_seats as usize;
    let draw = match parliament_iface::pause_draw(&state.world, pulse.pulse_id, sequence, seed, k) {
        Ok(draw) => draw,
        Err(_) => return Ok(()),
    };
    if !draw.matches(&state.world, pulse.pulse_id, sequence, seed) {
        return Err(StateBlockStartError::GovernanceDueUnavailable(
            super::super::keepalive::DueWorkUnavailable,
        ));
    }
    let reason = draw.unavailable.or_else(|| {
        (draw.count < 2 * k).then_some(SccpPausePanelUnavailableReasonV1::InsufficientCandidates)
    });
    if let Some(reason) = reason {
        let mut tx = state
            .try_transaction()
            .map_err(StateBlockStartError::Storage)?;
        tx.world.emit_events(Some(SccpEvent::PausePanelUnavailable(
            SccpPausePanelUnavailableV1 {
                pulse_id: pulse.pulse_id,
                reason,
            },
        )));
        tx.require_storage_admission()
            .map_err(StateBlockStartError::Storage)?;
        tx.apply();
        return state
            .require_storage_admission()
            .map_err(StateBlockStartError::Storage);
    }
    if draw.count > 3 * k || draw.count > MAX_DRAW {
        return Err(StateBlockStartError::Policy(
            "SCCP parent draw exceeds its bound".into(),
        ));
    }
    let first = draw.members[0]
        .ok_or_else(|| StateBlockStartError::Policy("SCCP parent draw is incomplete".into()))?;
    let mut members = [first; MAX_DRAW];
    for (index, slot) in members[..draw.count].iter_mut().enumerate() {
        *slot = draw.members[index]
            .ok_or_else(|| StateBlockStartError::Policy("SCCP parent draw is incomplete".into()))?;
    }
    let primary = *Hash::new_from_chunks(&[
        b"sccp/pause-panel-id/v1",
        &sequence.to_be_bytes(),
        &pulse.pulse_id,
        &[0],
    ])
    .as_ref();
    let backup = *Hash::new_from_chunks(&[
        b"sccp/pause-panel-id/v1",
        &sequence.to_be_bytes(),
        &pulse.pulse_id,
        &[1],
    ])
    .as_ref();
    let accept_until_ms = time
        .checked_add(parameters.fast_pause_seat_accept_window_ms)
        .ok_or_else(|| {
            StateBlockStartError::Policy("SCCP seat acceptance deadline exhausted".into())
        })?;
    let term_ends_at_ms = time
        .checked_add(parameters.fast_pause_panel_term_ms)
        .ok_or_else(|| StateBlockStartError::Policy("SCCP panel term exhausted".into()))?;
    let draft = PausePanelDraft {
        panel_seq: sequence,
        pulse_id: pulse.pulse_id,
        seated_height: state._curr_block.height().get(),
        seated_at_ms: time,
        accept_until_ms,
        term_ends_at_ms,
        drawn: &members[..draw.count],
        accepted: &[],
        primary_id: primary,
        backup_id: backup,
    };
    let budget = state.execution_budget();
    let next = RetainedSccpPausePanel::admit_draft(&draft, &budget);
    let event = SccpEvent::PausePanelSeated(SccpPausePanelSeatedV1 {
        panel_seq: sequence,
        pulse_id: pulse.pulse_id,
        primary_id: primary,
        backup_id: backup,
        seated_height: draft.seated_height,
        seated_at_ms: time,
        accept_until_ms,
        term_ends_at_ms,
        drawn_count: u32::try_from(draw.count)
            .map_err(|_| StateBlockStartError::Policy("SCCP drawn count exceeds u32".into()))?,
    });
    let mut tx = state
        .try_transaction()
        .map_err(StateBlockStartError::Storage)?;
    let next = next.map_err(|error| construction_error(&mut tx, error));
    tx.require_storage_admission()
        .map_err(StateBlockStartError::Storage)?;
    store::pause_panel::set(
        &mut tx,
        Some(next.map_err(|error| StateBlockStartError::Policy(error.to_string()))?),
    );
    tx.world.emit_events(Some(event));
    tx.require_storage_admission()
        .map_err(StateBlockStartError::Storage)?;
    tx.apply();
    state
        .require_storage_admission()
        .map_err(StateBlockStartError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_pause_panel};

    #[test]
    fn sccp_pause_draw_never_uses_a_plain_state_block_as_boundary_authority() {
        for existing in [false, true] {
            let state = blank_state();
            let mut block = state.block(header(2));
            let original = {
                let mut tx = block.transaction();
                store::parameters::set(&mut tx, Some(SccpParametersV1::taira_default()));
                let panel = existing.then(|| {
                    let mut panel = sample_pause_panel(1);
                    panel.term_ends_at_ms = tx.block_unix_timestamp_ms();
                    // Existing fixture deadlines are below this block's time.
                    panel.accept_until_ms = panel.seated_at_ms + 1;
                    RetainedSccpPausePanel::admit(&panel, tx.sccp_evidence_preparation_budget())
                        .unwrap()
                });
                store::pause_panel::set(&mut tx, panel.clone());
                tx.apply();
                panel
            };
            assert!(block.sumeragi_schedule.original_native_pulse().is_none());
            at_boundary::<()>(&mut block).unwrap();
            assert_eq!(store::pause_panel::get(&block.world), &original);
        }
    }
}
