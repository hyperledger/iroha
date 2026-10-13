//! Same-pass certificate production and rechecked enactment; DATA grants no authority.

use super::*;
use crate::state::{StateBlock, StateBlockStartError};
use iroha_crypto::{
    Hash,
    blake2::{
        Blake2bVar,
        digest::{Update, VariableOutput},
    },
};
use iroha_data_model::sccp::{
    events::{SccpFastPauseEnactedV1, SccpFastPauseNoResultV1},
    fast_pause::{SccpFastPauseCertificateId, SccpFastPauseCertificateV1, SccpPassPositionV1},
};

/// Ephemeral certificate from this exact pass. No public constructor or persistence decoder.
pub(in crate::smartcontracts::isi::sccp) struct CertifiedPause {
    certificate: SccpFastPauseCertificateV1,
    round: RetainedSccpFastPauseRound,
    source: mv::BlockPublicationIdentity,
    header: iroha_data_model::block::BlockHeader,
}
/// Only an enactment that completed every current-state recheck may issue track-two controls.
pub(in crate::smartcontracts::isi::sccp) struct EnactingPause(SccpFastPauseCertificateV1);
impl EnactingPause {
    pub(in crate::smartcontracts::isi::sccp) fn cause(&self) -> ([u8; 32], [u8; 32]) {
        (
            *SccpFastPauseCertificateId::derive_v1(&self.0).as_bytes(),
            self.0.effect_preimage_hash,
        )
    }
}

fn recheck(
    world: &(impl WorldReadOnly + ?Sized),
    panel: &PausePanelBody,
    round: &super::super::pause_record::FastPauseRoundBody,
    network: SccpNetworkV1,
    role: SccpPanelRoleV1,
    time: u64,
    eligible: u32,
) -> Result<([bool; MAX_DRAW], u32), NoResult> {
    let parameters = store::parameters::get(world)
        .as_ref()
        .ok_or(NoResult::NoLiveRevision)?;
    conditions(world, network, round.head, time, parameters)?;
    if time >= round.closes_at_ms && !cfg!(all(test, sumeragi_core_mutation = "HC297")) {
        return Err(NoResult::Expired);
    }
    if panel.panel_seq != round.panel_seq || role_of(panel, &round.panel_id) != Some(role) {
        return Err(NoResult::PanelChanged);
    }
    let k = parameters.fast_pause_panel_seats as usize;
    let eligible = if cfg!(all(test, sumeragi_core_mutation = "HC296")) {
        u32::MAX
    } else {
        eligible
    };
    let owners = seats(panel, k, time, eligible).map_err(|_| NoResult::PanelChanged)?;
    let mut selected = [false; MAX_DRAW];
    let mut count = 0;
    if round.endorsers.len() > MAX_DRAW {
        return Err(NoResult::InsufficientEligibleEndorsements);
    }
    for (index, (account, _)) in round.endorsers.iter().enumerate() {
        selected[index] = counts(panel, &owners, role, k, eligible, account);
        count += u32::from(selected[index]);
    }
    if count < parameters.fast_pause_panel_quorum() {
        return Err(NoResult::InsufficientEligibleEndorsements);
    }
    Ok((selected, count))
}

// Raw Blake2b fingerprint matches the model domains, but streams canonical Norito bytes.
struct FingerprintWriter(Blake2bVar);
impl std::io::Write for FingerprintWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn fingerprint(
    domain: &[u8],
    value: &impl norito::core::SerializePayload,
) -> Result<[u8; 32], Error> {
    use std::io::Write;
    let mut writer =
        FingerprintWriter(Blake2bVar::new(32).map_err(|_| refuse("fingerprint width"))?);
    writer
        .write_all(&(domain.len() as u64).to_le_bytes())
        .map_err(refuse)?;
    writer.write_all(domain).map_err(refuse)?;
    norito::codec::encode_adaptive_into(value, &mut writer).map_err(refuse)?;
    let mut result = [0; 32];
    writer.0.finalize_variable(&mut result).map_err(refuse)?;
    Ok(result)
}
/// The roots bind canonical account order, each signed incident and its committed height.
/// Account payload lengths are explicit; no concatenation or account graph is allocated.
fn roots(
    round: &super::super::pause_record::FastPauseRoundBody,
    selected: &[bool; MAX_DRAW],
    count: u32,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let endorsements = Hash::new_from_writer(|mut writer| {
        writer.write_all(b"sccp/pause-endorsements/v1")?;
        writer.write_all(&count.to_be_bytes())?;
        for (index, (account, fact)) in round
            .endorsers
            .iter()
            .enumerate()
            .filter(|(i, _)| selected[*i])
        {
            let _ = index;
            let len = norito::codec::encode_adaptive_into(account, &mut std::io::sink())
                .map_err(std::io::Error::other)?;
            writer.write_all(
                &u64::try_from(len)
                    .map_err(std::io::Error::other)?
                    .to_be_bytes(),
            )?;
            norito::codec::encode_adaptive_into(account, &mut writer)
                .map_err(std::io::Error::other)?;
            writer.write_all(&fact.incident_digest)?;
            writer.write_all(&fact.recorded_at_height.to_be_bytes())?;
        }
        Ok(())
    })
    .map_err(refuse)?;
    let incidents = Hash::new_from_writer(|writer| {
        writer.write_all(b"sccp/pause-incidents/v1")?;
        writer.write_all(&count.to_be_bytes())?;
        for (index, (_, fact)) in round.endorsers.iter().enumerate() {
            if selected[index] {
                writer.write_all(&fact.incident_digest)?;
            }
        }
        Ok(())
    })
    .map_err(refuse)?;
    Ok((*endorsements.as_ref(), *incidents.as_ref()))
}

fn no_result<E: std::fmt::Debug>(
    state: &mut StateBlock<'_>,
    network: SccpNetworkV1,
    role: SccpPanelRoleV1,
    panel_id: [u8; 32],
    reason: NoResult,
) -> Result<(), StateBlockStartError<E>> {
    let mut tx = state
        .try_transaction()
        .map_err(StateBlockStartError::Storage)?;
    store::fast_pause_rounds::remove(&mut tx, (network, role));
    tx.world.emit_events(Some(SccpEvent::FastPauseNoResult(
        SccpFastPauseNoResultV1 {
            network,
            panel_id,
            reason,
        },
    )));
    tx.require_storage_admission()
        .map_err(StateBlockStartError::Storage)?;
    tx.apply();
    state
        .require_storage_admission()
        .map_err(StateBlockStartError::Storage)
}

/// Called only for one cost-one position issued by the shared rank-three cursor.
pub(in crate::smartcontracts::isi::sccp) fn certify<E: std::fmt::Debug>(
    state: &mut StateBlock<'_>,
    network: SccpNetworkV1,
    role: SccpPanelRoleV1,
) -> Result<Option<CertifiedPause>, StateBlockStartError<E>> {
    let Some(round) = store::fast_pause_rounds::get(&state.world, &(network, role))
        .filter(|round| round.certify_due)
        .cloned()
    else {
        return Ok(None);
    };
    let time = state._curr_block.creation_time_ms;
    let Some(panel) = store::pause_panel::get(&state.world).as_ref() else {
        no_result(state, network, role, round.panel_id, NoResult::PanelChanged)?;
        return Ok(None);
    };
    let eligible = parliament_iface::pause_eligibility(&state.world, panel, time)
        .and_then(|observation| observation.for_original(&state.world, panel, time))
        .map_err(|_| {
            StateBlockStartError::GovernanceDueUnavailable(
                super::super::keepalive::DueWorkUnavailable,
            )
        })?;
    let (selected, count) =
        match recheck(&state.world, panel, &round, network, role, time, eligible) {
            Ok(result) => result,
            Err(reason) => {
                no_result(state, network, role, round.panel_id, reason)?;
                return Ok(None);
            }
        };
    let (endorsement_root, incident_root) = roots(&round, &selected, count)
        .map_err(|error| StateBlockStartError::Policy(error.to_string()))?;
    let effect_preimage_hash = fingerprint(
        iroha_data_model::sccp::fast_pause::SCCP_FAST_PAUSE_EFFECT_V1,
        &(*state.network_id(), network, round.head),
    )
    .map_err(|error| StateBlockStartError::Policy(error.to_string()))?;
    let parameters = store::parameters::get(&state.world)
        .as_ref()
        .ok_or_else(|| {
            StateBlockStartError::Policy("SCCP disappeared during certification".into())
        })?;
    Ok(Some(CertifiedPause {
        certificate: SccpFastPauseCertificateV1 {
            network_id: *state.network_id(),
            network,
            panel_id: round.panel_id,
            panel_role: role,
            panel_seq: round.panel_seq,
            head: round.head,
            endorsement_root,
            endorsement_count: count,
            quorum: parameters.fast_pause_panel_quorum(),
            incident_root,
            effect_preimage_hash,
            certified_at_height: state._curr_block.height().get(),
            certified_at_ms: time,
        },
        round,
        source: state.world.sccp_fast_pause_rounds.publication_identity(),
        header: state._curr_block,
    }))
}

/// Derive all destination parts before changing a nonce, hold or leaf.
fn control_parts(
    route: &iroha_data_model::sccp::registry::SccpRouteV1,
    occupied: usize,
) -> Result<
    (
        [u32; super::super::leaves::MAX_LEAVES_PER_BLOCK as usize],
        usize,
    ),
    NoResult,
> {
    const CAP: usize = super::super::leaves::MAX_LEAVES_PER_BLOCK as usize;
    let available = if cfg!(all(test, sumeragi_core_mutation = "HC301")) {
        CAP
    } else {
        CAP.saturating_sub(occupied)
    };
    let mut parts = [0; CAP];
    let mut count = 0;
    for revision in route.revisions.values().filter(|revision| {
        matches!(
            revision.activation,
            SccpRouteActivationV1::Bidirectional
                | SccpRouteActivationV1::Paused
                | SccpRouteActivationV1::InboundOnly
        )
    }) {
        if count == available {
            return Err(NoResult::ControlCapacity);
        }
        if revision.next_control_nonce == u64::MAX {
            return Err(NoResult::CounterExhausted);
        }
        parts[count] = revision.revision;
        count += 1;
    }
    if count == 0 {
        return Err(NoResult::NoLiveRevision);
    }
    Ok((parts, count))
}

/// Recheck after every Parliament enactment in the same original positioned pass.
pub(in crate::smartcontracts::isi::sccp) fn enact<E: std::fmt::Debug>(
    state: &mut StateBlock<'_>,
    original: CertifiedPause,
    position: u32,
) -> Result<(), StateBlockStartError<E>> {
    let cert = original.certificate;
    let network = cert.network;
    let role = cert.panel_role;
    if original.source != state.world.sccp_fast_pause_rounds.publication_identity()
        || original.header != state._curr_block
    {
        return Err(StateBlockStartError::GovernanceDueUnavailable(
            super::super::keepalive::DueWorkUnavailable,
        ));
    }
    let time = state._curr_block.creation_time_ms;
    let Some(panel) = store::pause_panel::get(&state.world).as_ref() else {
        return no_result(state, network, role, cert.panel_id, NoResult::PanelChanged);
    };
    let eligible = parliament_iface::pause_eligibility(&state.world, panel, time)
        .and_then(|observation| observation.for_original(&state.world, panel, time))
        .map_err(|_| {
            StateBlockStartError::GovernanceDueUnavailable(
                super::super::keepalive::DueWorkUnavailable,
            )
        })?;
    if let Err(reason) = recheck(
        &state.world,
        panel,
        &original.round,
        network,
        role,
        time,
        eligible,
    ) {
        return no_result(state, network, role, cert.panel_id, reason);
    }
    if store::fast_pause_rounds::get(&state.world, &(network, role)) != Some(&original.round) {
        return no_result(state, network, role, cert.panel_id, NoResult::PanelChanged);
    }
    let Some(parameters) = store::parameters::get(&state.world).as_ref() else {
        return no_result(
            state,
            network,
            role,
            cert.panel_id,
            NoResult::NoLiveRevision,
        );
    };
    let Some(until) = time.checked_add(parameters.fast_pause_hold_ms) else {
        return no_result(
            state,
            network,
            role,
            cert.panel_id,
            NoResult::CounterExhausted,
        );
    };
    let Some(next_head) = cert.head.checked_add(1) else {
        return no_result(
            state,
            network,
            role,
            cert.panel_id,
            NoResult::CounterExhausted,
        );
    };
    let route = store::routes::get(&state.world, &network)
        .ok_or_else(|| StateBlockStartError::Policy("SCCP live route disappeared".into()))?;
    let (revisions, count) = match control_parts(
        route,
        super::super::leaves::leaf_count_at(&state.world, state._curr_block.height().get()),
    ) {
        Ok(parts) => parts,
        Err(reason) => return no_result(state, network, role, cert.panel_id, reason),
    };
    let renewal =
        store::fast_pauses::get(&state.world, &network).is_some_and(|pause| time < pause.until_ms);
    let effect = EnactingPause(cert);
    let cause = super::super::controls::ControlCauseV1::from_fast_pause(&effect);
    let certificate_id = SccpFastPauseCertificateId::derive_v1(&cert);
    let mut tx = state
        .try_transaction()
        .map_err(StateBlockStartError::Storage)?;
    let result = (|| {
        let next = super::super::pause_record::RetainedSccpFastPause::admit_draft(
            &super::super::pause_record::FastPauseDraft {
                certificate_id: *certificate_id.as_bytes(),
                effect_hash: cert.effect_preimage_hash,
                panel_id: cert.panel_id,
                enacted_at: SccpPassPositionV1 {
                    height: cert.certified_at_height,
                    position,
                },
                enacted_at_ms: time,
                until_ms: until,
                taira: true,
                revisions: &revisions[..count],
            },
            tx.sccp_evidence_preparation_budget(),
        )
        .map_err(|error| construction_error(&mut tx, error))?;
        store::fast_pauses::insert(&mut tx, network, next)?;
        for revision in &revisions[..count] {
            super::super::controls::record_control(&mut tx, network, *revision, cause)?;
        }
        store::set_governance_revision(
            &mut tx,
            SccpGovernanceSubjectV1::FastHold(network),
            next_head,
        );
        store::fast_pause_rounds::remove(&mut tx, (network, SccpPanelRoleV1::Primary));
        store::fast_pause_rounds::remove(&mut tx, (network, SccpPanelRoleV1::Backup));
        tx.world
            .emit_events(Some(SccpEvent::FastPauseEnacted(SccpFastPauseEnactedV1 {
                network,
                certificate_id,
                until_ms: until,
                renewal,
            })));
        Ok::<(), Error>(())
    })();
    tx.require_storage_admission()
        .map_err(StateBlockStartError::Storage)?;
    result.map_err(|error| StateBlockStartError::Policy(error.to_string()))?;
    tx.apply();
    state
        .require_storage_admission()
        .map_err(StateBlockStartError::Storage)
}

#[cfg(test)]
mod tests;
