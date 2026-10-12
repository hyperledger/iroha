//! Mandatory SCCP v1 snapshot envelope with exact MV predecessors (`specs/sccp.md` §4).
//!
//! Every SCCP world store is keyed by compound or binary keys that have no JSON key codec, so
//! this module persists them as canonical bare Norito records through the shared snapshot
//! storage envelope, and the SCCP cells through their current/predecessor JSON envelopes. The State snapshot carries the envelope under one `sccp` member, bound to the
//! same publication generation as World. Decoding validates structural key/value agreement
//! before any field is published and never derives a predecessor from current state.
//!
//! Owner: ws20 (layout). The structural key/value invariants checked here are each map's
//! `valid_entry` rule in `crate::smartcontracts::isi::sccp::store`, the single write funnel,
//! whose `insert` refuses an entry that breaks it; so every committed state restores. Semantic
//! invariants of the stored records are enforced by the SCCP instructions and hooks that write
//! them (ws30–ws33, ws41).

use super::*;
use crate::smartcontracts::isi::sccp::{
    anchor_record::{AnchorRecordError, RetainedSccpAnchors},
    generation_record::{GenerationRecordError, RetainedSccpGeneration},
    pause_record::{
        PauseRecordError, RetainedSccpFastPause, RetainedSccpFastPauseRound, RetainedSccpPausePanel,
    },
    store,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};

/// Snapshot syntax and original resource refusal remain distinct through the State reader.
#[derive(Debug, thiserror::Error)]
pub enum SccpRestoreError {
    /// Malformed canonical current or predecessor data.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// The complete current/undo graph was refused before any partial owner was created.
    #[error("snapshot SCCP original graph admission refused: {0}")]
    Admission(#[from] AllocationRefusal),
    /// Generation graph admission refused; original allocation identity is retained.
    #[error("sccp_committee_generations: {0}")]
    Generation(#[from] GenerationRecordError),
    /// Open-anchor graph admission refused; original allocation identity is retained.
    #[error("sccp_anchor_open: {0}")]
    Anchors(#[from] AnchorRecordError),
    /// Pause, panel or endorsement graph failed without discarding its original refusal.
    #[error("SCCP pause State: {0}")]
    Pause(#[from] PauseRecordError),
}

/// Admit every immutable graph before constructing the replacement storage.
/// TODO: fund the enclosing decoded map and MV map-node allocations at their owners.
fn admit_generations(
    decoded: &Storage<u64, SccpCommitteeGenerationV1>,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<Storage<u64, RetainedSccpGeneration>, SccpRestoreError> {
    let snapshot = decoded.snapshot();
    let mut current = BTreeMap::new();
    let mut undo = BTreeMap::new();
    for (key, value) in snapshot.current().iter() {
        current.insert(
            *key,
            RetainedSccpGeneration::admit_prepaid(value, budget, reservation)?,
        );
    }
    for (key, value) in snapshot.revert_map().iter() {
        undo.insert(
            *key,
            value
                .as_ref()
                .map(|value| RetainedSccpGeneration::admit_prepaid(value, budget, reservation))
                .transpose()?,
        );
    }
    Ok(Storage::from_snapshot_parts(current, undo))
}

/// Preserve exact predecessor presence while admitting both actual anchor allocations.
/// TODO: fund the enclosing Cell EBR allocations at the State cell owner.
fn admit_anchors(
    decoded: &Cell<Vec<SccpAnchorV1>>,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<Cell<RetainedSccpAnchors>, SccpRestoreError> {
    let current = RetainedSccpAnchors::admit_prepaid(decoded.view().get(), budget, reservation)?;
    let undo = decoded
        .predecessor_view()
        .get()
        .as_ref()
        .map(|value| RetainedSccpAnchors::admit_prepaid(value, budget, reservation))
        .transpose()?;
    Ok(Cell::from_values_charged(
        current,
        undo,
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    ))
}
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        commitment::{SccpBlockCommitmentV1, SccpHistoryStateV1},
        control::{SccpControlRecordV1, SccpLeafRefV1},
        fast_pause::{SccpFastPauseRoundV1, SccpFastPauseV1, SccpPanelRoleV1, SccpPausePanelV1},
        generation::{SCCP_ANCHOR_CHUNK_SIZE_V1, SccpAnchorV1, SccpCommitteeGenerationV1},
        governance::SccpGovernanceSubjectV1,
        inbound::SccpInboundRecordV1,
        light_client::{
            SccpLcCheckpointV1, SccpLcConsensusSetV1, SccpLcProfileActivationV1, SccpLightClientV1,
        },
        outbound::SccpOutboundMessageRecordV1,
        params::SccpParametersV1,
        registry::SccpRouteV1,
    },
};
use norito::json::JsonSerialize as _;

/// Admit all current and exact predecessor pause records from the same aggregate credit.
/// TODO: fund the enclosing decoded map and MV map-node allocations at their owners.
fn admit_pause_map<K: mv::Key, V: mv::Value, R: mv::Value>(
    decoded: &Storage<K, V>,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
    admit: impl Fn(&V, &AllocationBudget, &mut AllocationReservation) -> Result<R, PauseRecordError>,
) -> Result<Storage<K, R>, SccpRestoreError> {
    let snapshot = decoded.snapshot();
    let mut current = BTreeMap::new();
    let mut undo = BTreeMap::new();
    for (key, value) in snapshot.current().iter() {
        current.insert(key.clone(), admit(value, budget, reservation)?);
    }
    for (key, value) in snapshot.revert_map().iter() {
        undo.insert(
            key.clone(),
            value
                .as_ref()
                .map(|value| admit(value, budget, reservation))
                .transpose()?,
        );
    }
    Ok(Storage::from_snapshot_parts(current, undo))
}

/// Preserve absent predecessors separately from a predecessor whose panel is absent.
/// TODO: fund the enclosing Cell EBR allocations at the State cell owner.
fn admit_panel(
    decoded: &Cell<Option<SccpPausePanelV1>>,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<Cell<Option<RetainedSccpPausePanel>>, SccpRestoreError> {
    let mut admit = |value: &Option<SccpPausePanelV1>| {
        value
            .as_ref()
            .map(|panel| RetainedSccpPausePanel::admit_prepaid(panel, budget, reservation))
            .transpose()
    };
    let current = admit(decoded.view().get())?;
    let undo = decoded
        .predecessor_view()
        .get()
        .as_ref()
        .map(admit)
        .transpose()?;
    Ok(Cell::from_values_charged(
        current,
        undo,
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    ))
}

/// Enumerate current and exact undo payloads; deleted undo entries carry no graph.
fn pause_map_demand<K: mv::Key, V: mv::Value>(
    decoded: &Storage<K, V>,
    demand: impl Fn(&V) -> Result<usize, PauseRecordError>,
    add: &mut impl FnMut(usize) -> Result<(), AllocationRefusal>,
) -> Result<(), SccpRestoreError> {
    let snapshot = decoded.snapshot();
    for (_, value) in snapshot.current().iter() {
        add(demand(value)?)?;
    }
    for (_, value) in snapshot.revert_map().iter() {
        if let Some(value) = value {
            add(demand(value)?)?;
        }
    }
    Ok(())
}

/// Compute all actual retained data/control allocations before requesting any credit.
fn snapshot_graph_demand(
    generations: &Storage<u64, SccpCommitteeGenerationV1>,
    anchors: &Cell<Vec<SccpAnchorV1>>,
    fast_pauses: &Storage<SccpNetworkV1, SccpFastPauseV1>,
    rounds: &Storage<(SccpNetworkV1, SccpPanelRoleV1), SccpFastPauseRoundV1>,
    panel: &Cell<Option<SccpPausePanelV1>>,
) -> Result<usize, SccpRestoreError> {
    let mut bytes = 0usize;
    let mut add = |size: usize| -> Result<(), AllocationRefusal> {
        bytes = bytes
            .checked_add(size)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    };
    let generations = generations.snapshot();
    for (_, row) in generations.current().iter() {
        add(RetainedSccpGeneration::admission_demand(row)?)?;
    }
    for (_, row) in generations.revert_map().iter() {
        if let Some(row) = row {
            add(RetainedSccpGeneration::admission_demand(row)?)?;
        }
    }
    add(RetainedSccpAnchors::admission_demand(anchors.view().get())?)?;
    if let Some(prior) = anchors.predecessor_view().get() {
        add(RetainedSccpAnchors::admission_demand(prior)?)?;
    }
    pause_map_demand(
        fast_pauses,
        RetainedSccpFastPause::admission_demand,
        &mut add,
    )?;
    pause_map_demand(
        rounds,
        RetainedSccpFastPauseRound::admission_demand,
        &mut add,
    )?;
    if let Some(panel) = panel.view().get() {
        add(RetainedSccpPausePanel::admission_demand(panel)?)?;
    }
    if let Some(Some(panel)) = panel.predecessor_view().get() {
        add(RetainedSccpPausePanel::admission_demand(panel)?)?;
    }
    Ok(bytes)
}

/// Name of the State snapshot member that carries this envelope.
pub(crate) const SCCP_SNAPSHOT_MEMBER: &str = "sccp";

/// Required SCCP wire fields; every store includes both current and exact undo maps.
/// Unknown fields are rejected, including fields of the retired attestation transport.
#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(crate) struct SnapshotSccpState {
    pub(super) sccp_parameters: Cell<Option<SccpParametersV1>>,
    pub(super) sccp_reset_nonce: Cell<Option<[u8; 32]>>,
    pub(super) sccp_committee_generations: snapshot_storage::SnapshotStorage,
    pub(super) sccp_committee_current: Cell<u64>,
    pub(super) sccp_liability_clock: Cell<u64>,
    pub(super) sccp_degraded_run: Cell<u32>,
    pub(super) sccp_anchor_open: Cell<Vec<SccpAnchorV1>>,
    pub(super) sccp_anchor_chunks: snapshot_storage::SnapshotStorage,
    pub(super) sccp_block_leaves: snapshot_storage::SnapshotStorage,
    pub(super) sccp_block_commitments: snapshot_storage::SnapshotStorage,
    pub(super) sccp_history: Cell<SccpHistoryStateV1>,
    pub(super) sccp_history_leaves: snapshot_storage::SnapshotStorage,
    pub(super) sccp_outbound_messages: snapshot_storage::SnapshotStorage,
    pub(super) sccp_outbound_by_nonce: snapshot_storage::SnapshotStorage,
    pub(super) sccp_control_messages: snapshot_storage::SnapshotStorage,
    pub(super) sccp_fast_pauses: snapshot_storage::SnapshotStorage,
    pub(super) sccp_fast_pause_suspended_until_ms: snapshot_storage::SnapshotStorage,
    pub(super) sccp_fast_pause_rounds: snapshot_storage::SnapshotStorage,
    pub(super) sccp_pause_panel: Cell<Option<SccpPausePanelV1>>,
    pub(super) sccp_routes: snapshot_storage::SnapshotStorage,
    pub(super) sccp_destination_words: snapshot_storage::SnapshotStorage,
    pub(super) sccp_governance_revisions: snapshot_storage::SnapshotStorage,
    pub(super) sccp_inbound_messages: snapshot_storage::SnapshotStorage,
    pub(super) sccp_pending_counts: snapshot_storage::SnapshotStorage,
    pub(super) sccp_light_clients: snapshot_storage::SnapshotStorage,
    pub(super) sccp_light_client_sets: snapshot_storage::SnapshotStorage,
    pub(super) sccp_light_client_checkpoints: snapshot_storage::SnapshotStorage,
    pub(super) sccp_light_client_stride_index: snapshot_storage::SnapshotStorage,
    pub(super) sccp_light_client_profiles: snapshot_storage::SnapshotStorage,
}

/// Append the key of one envelope member, preceded by a comma after the first member.
fn member(out: &mut String, first: &mut bool, name: &str) {
    if !*first {
        out.push(',');
    }
    *first = false;
    json::write_json_string(name, out);
    out.push(':');
}

/// Serialize one member as a cell envelope or a storage envelope.
macro_rules! serialize_sccp_member {
    (cell, $world:expr, $out:expr, $serialize:ident, $field:ident) => {
        $world.$field.json_serialize($out)
    };
    (store, $world:expr, $out:expr, $serialize:ident, $field:ident) => {
        snapshot_storage::$serialize(&$world.$field, $out)
    };
}

/// Write the envelope members of `$world` in canonical field order.
macro_rules! serialize_sccp_fields {
    ($world:expr, $out:expr, $serialize:ident) => {
        serialize_sccp_fields!(@members $world, $out, $serialize;
            cell sccp_parameters,
            cell sccp_reset_nonce,
            store sccp_committee_generations,
            cell sccp_committee_current,
            cell sccp_liability_clock,
            cell sccp_degraded_run,
            cell sccp_anchor_open,
            store sccp_anchor_chunks,
            store sccp_block_leaves,
            store sccp_block_commitments,
            cell sccp_history,
            store sccp_history_leaves,
            store sccp_outbound_messages,
            store sccp_outbound_by_nonce,
            store sccp_control_messages,
            store sccp_fast_pauses,
            store sccp_fast_pause_suspended_until_ms,
            store sccp_fast_pause_rounds,
            cell sccp_pause_panel,
            store sccp_routes,
            store sccp_destination_words,
            store sccp_governance_revisions,
            store sccp_inbound_messages,
            store sccp_pending_counts,
            store sccp_light_clients,
            store sccp_light_client_sets,
            store sccp_light_client_checkpoints,
            store sccp_light_client_stride_index,
            store sccp_light_client_profiles,
        )
    };
    (@members $world:expr, $out:expr, $serialize:ident; $($kind:ident $field:ident,)*) => {{
        let mut first = true;
        $out.push('{');
        $(
            member($out, &mut first, stringify!($field));
            serialize_sccp_member!($kind, $world, $out, $serialize, $field);
        )*
        $out.push('}');
    }};
}

/// Append `,"sccp":{..}` for the committed World under the outer State capture fence.
pub(crate) fn serialize(world: &World, out: &mut String) {
    out.push(',');
    json::write_json_string(SCCP_SNAPSHOT_MEMBER, out);
    out.push(':');
    serialize_envelope(world, out);
}

/// Append `,"sccp":{..}` for the exact maps and cells that consuming this World overlay would
/// publish.
#[cfg(test)]
pub(crate) fn serialize_block(world: &WorldBlock<'_>, out: &mut String) {
    out.push(',');
    json::write_json_string(SCCP_SNAPSHOT_MEMBER, out);
    out.push(':');
    serialize_block_envelope(world, out);
}

/// Write the bare envelope object of the committed World.
pub(crate) fn serialize_envelope(world: &World, out: &mut String) {
    serialize_sccp_fields!(world, out, serialize);
}

/// Write the bare envelope object of a World overlay.
#[cfg(test)]
pub(crate) fn serialize_block_envelope(world: &WorldBlock<'_>, out: &mut String) {
    serialize_sccp_fields!(world, out, serialize_block);
}

fn invalid(field: &str, message: impl Into<String>) -> json::Error {
    json::Error::InvalidField {
        field: format!("state.{SCCP_SNAPSHOT_MEMBER}.{field}"),
        message: message.into(),
    }
}

/// Validate one SCCP cell's current and predecessor values with the same rule.
fn validate_cell<T: mv::Value>(
    cell: &Cell<T>,
    field: &str,
    rule: impl Fn(&T) -> Result<(), String>,
) -> Result<(), json::Error> {
    rule(cell.view().get()).map_err(|message| invalid(field, message))?;
    if let Some(prior) = cell.predecessor_view().get() {
        rule(prior).map_err(|message| invalid(field, format!("predecessor: {message}")))?;
    }
    Ok(())
}

fn valid_parameters(parameters: &Option<SccpParametersV1>) -> Result<(), String> {
    parameters.as_ref().map_or(Ok(()), |parameters| {
        parameters.validate().map_err(|error| error.to_string())
    })
}

fn valid_reset_nonce(nonce: &Option<[u8; 32]>) -> Result<(), String> {
    if nonce.is_some_and(|nonce| nonce == [0; 32]) {
        return Err("the reset nonce must be nonzero".to_owned());
    }
    Ok(())
}

fn valid_history(history: &SccpHistoryStateV1) -> Result<(), String> {
    if history.is_well_formed() {
        Ok(())
    } else {
        Err("history peaks do not match the accumulator size".to_owned())
    }
}

fn valid_anchor_open(anchors: &[SccpAnchorV1]) -> Result<(), String> {
    if anchors.len() < SCCP_ANCHOR_CHUNK_SIZE_V1 {
        Ok(())
    } else {
        Err("a completed anchor chunk must be closed, not retained in the open cell".to_owned())
    }
}

impl SnapshotSccpState {
    /// Decode and validate every current/predecessor envelope before publishing any field.
    pub(super) fn restore(
        self,
        world: &mut World,
        budget: &AllocationBudget,
    ) -> Result<(), SccpRestoreError> {
        validate_cell(&self.sccp_parameters, "sccp_parameters", valid_parameters)?;
        validate_cell(
            &self.sccp_reset_nonce,
            "sccp_reset_nonce",
            valid_reset_nonce,
        )?;
        validate_cell(&self.sccp_history, "sccp_history", valid_history)?;
        validate_cell(&self.sccp_anchor_open, "sccp_anchor_open", |value| {
            valid_anchor_open(value)
        })?;
        validate_cell(&self.sccp_pause_panel, "sccp_pause_panel", |value| {
            if value.as_ref().is_none_or(SccpPausePanelV1::has_valid_shape) {
                Ok(())
            } else {
                Err("invalid panel structure".to_owned())
            }
        })?;
        let committee_generations = self
            .sccp_committee_generations
            .decode::<u64, SccpCommitteeGenerationV1>(
                "sccp_committee_generations",
                |key, value| *key == value.generation && value.is_well_formed(),
            )?;
        let anchor_chunks = self
            .sccp_anchor_chunks
            .decode::<u64, [u8; 32]>("sccp_anchor_chunks", store::anchor_chunks::valid_entry)?;
        let block_leaves = self.sccp_block_leaves.decode::<(u64, u32), SccpLeafRefV1>(
            "sccp_block_leaves",
            store::block_leaves::valid_entry,
        )?;
        let block_commitments = self
            .sccp_block_commitments
            .decode::<u64, SccpBlockCommitmentV1>(
                "sccp_block_commitments",
                store::block_commitments::valid_entry,
            )?;
        let history_leaves = self
            .sccp_history_leaves
            .decode::<u64, (u64, [u8; 32])>("sccp_history_leaves", |_, _| true)?;
        let outbound_messages = self
            .sccp_outbound_messages
            .decode::<[u8; 32], SccpOutboundMessageRecordV1>("sccp_outbound_messages", |_, _| {
                true
            })?;
        let outbound_by_nonce = self
            .sccp_outbound_by_nonce
            .decode::<(SccpNetworkV1, u32, u64), [u8; 32]>("sccp_outbound_by_nonce", |_, _| true)?;
        let control_messages = self
            .sccp_control_messages
            .decode::<(SccpNetworkV1, u32, u64), SccpControlRecordV1>(
                "sccp_control_messages",
                store::control_messages::valid_entry,
            )?;
        let fast_pauses = self
            .sccp_fast_pauses
            .decode::<SccpNetworkV1, SccpFastPauseV1>("sccp_fast_pauses", |key, value| {
                key.is_external() && value.has_valid_shape()
            })?;
        let suspended = self
            .sccp_fast_pause_suspended_until_ms
            .decode::<SccpNetworkV1, u64>(
                "sccp_fast_pause_suspended_until_ms",
                store::fast_pause_suspended_until_ms::valid_entry,
            )?;
        let rounds = self
            .sccp_fast_pause_rounds
            .decode::<(SccpNetworkV1, SccpPanelRoleV1), SccpFastPauseRoundV1>(
                "sccp_fast_pause_rounds",
                |key, value| key.0.is_external() && value.has_valid_shape(),
            )?;
        let routes = self
            .sccp_routes
            .decode::<SccpNetworkV1, SccpRouteV1>("sccp_routes", store::routes::valid_entry)?;
        let destination_words = self
            .sccp_destination_words
            .decode::<[u8; 32], (SccpNetworkV1, u32)>("sccp_destination_words", |_, _| true)?;
        let governance_revisions = self
            .sccp_governance_revisions
            .decode::<SccpGovernanceSubjectV1, u64>(
                "sccp_governance_revisions",
                store::governance_revisions::valid_entry,
            )?;
        let inbound_messages = self
            .sccp_inbound_messages
            .decode::<[u8; 32], SccpInboundRecordV1>("sccp_inbound_messages", |_, _| true)?;
        let pending_counts = self
            .sccp_pending_counts
            .decode::<(SccpNetworkV1, u32), (u64, u64)>(
                "sccp_pending_counts",
                store::pending_counts::valid_entry,
            )?;
        let light_clients = self
            .sccp_light_clients
            .decode::<SccpNetworkV1, SccpLightClientV1>("sccp_light_clients", |_, _| true)?;
        let light_client_sets = self
            .sccp_light_client_sets
            .decode::<(SccpNetworkV1, u64), SccpLcConsensusSetV1>(
                "sccp_light_client_sets",
                |_, _| true,
            )?;
        let light_client_checkpoints = self
            .sccp_light_client_checkpoints
            .decode::<(SccpNetworkV1, u64), SccpLcCheckpointV1>(
                "sccp_light_client_checkpoints",
                |_, _| true,
            )?;
        let light_client_stride_index = self
            .sccp_light_client_stride_index
            .decode::<(SccpNetworkV1, u64), u64>("sccp_light_client_stride_index", |_, _| true)?;
        let light_client_profiles = self
            .sccp_light_client_profiles
            .decode::<(SccpNetworkV1, u32), SccpLcProfileActivationV1>(
                "sccp_light_client_profiles",
                store::light_client_profiles::valid_entry,
            )?;
        // Every structural check and graph admission precedes the first World publication.
        let bytes = snapshot_graph_demand(
            &committee_generations,
            &self.sccp_anchor_open,
            &fast_pauses,
            &rounds,
            &self.sccp_pause_panel,
        )?;
        let mut reservation = budget.try_reserve_bytes(bytes)?;
        let committee_generations =
            admit_generations(&committee_generations, budget, &mut reservation)?;
        let anchor_open = admit_anchors(&self.sccp_anchor_open, budget, &mut reservation)?;
        let fast_pauses = admit_pause_map(
            &fast_pauses,
            budget,
            &mut reservation,
            RetainedSccpFastPause::admit_prepaid,
        )?;
        let rounds = admit_pause_map(
            &rounds,
            budget,
            &mut reservation,
            RetainedSccpFastPauseRound::admit_prepaid,
        )?;
        let panel = admit_panel(&self.sccp_pause_panel, budget, &mut reservation)?;
        debug_assert_eq!(reservation.remaining_bytes(), 0);
        world.sccp_parameters = self.sccp_parameters;
        world.sccp_reset_nonce = self.sccp_reset_nonce;
        world.sccp_committee_generations = committee_generations;
        world.sccp_committee_current = self.sccp_committee_current;
        world.sccp_liability_clock = self.sccp_liability_clock;
        world.sccp_degraded_run = self.sccp_degraded_run;
        world.sccp_anchor_open = anchor_open;
        world.sccp_anchor_chunks = anchor_chunks;
        world.sccp_block_leaves = block_leaves;
        world.sccp_block_commitments = block_commitments;
        world.sccp_history = self.sccp_history;
        world.sccp_history_leaves = history_leaves;
        world.sccp_outbound_messages = outbound_messages;
        world.sccp_outbound_by_nonce = outbound_by_nonce;
        world.sccp_control_messages = control_messages;
        world.sccp_fast_pauses = fast_pauses;
        world.sccp_fast_pause_suspended_until_ms = suspended;
        world.sccp_fast_pause_rounds = rounds;
        world.sccp_pause_panel = panel;
        world.sccp_routes = routes;
        world.sccp_destination_words = destination_words;
        world.sccp_governance_revisions = governance_revisions;
        world.sccp_inbound_messages = inbound_messages;
        world.sccp_pending_counts = pending_counts;
        world.sccp_light_clients = light_clients;
        world.sccp_light_client_sets = light_client_sets;
        world.sccp_light_client_checkpoints = light_client_checkpoints;
        world.sccp_light_client_stride_index = light_client_stride_index;
        world.sccp_light_client_profiles = light_client_profiles;
        Ok(())
    }
}

#[cfg(test)]
#[path = "sccp_snapshot_state_tests.rs"]
pub(crate) mod tests;
