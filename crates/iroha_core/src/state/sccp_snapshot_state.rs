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
use crate::smartcontracts::isi::sccp::{anchors::SccpAnchorV1, store};
use crate::state::deserialize::StateRestoreError;
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        commitment::{SccpBlockCommitmentV1, SccpHistoryStateV1},
        control::{SccpControlRecordV1, SccpLeafRefV1},
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

/// Name of the State snapshot member that carries this envelope.
pub(crate) const SCCP_SNAPSHOT_MEMBER: &str = "sccp";

/// Required SCCP wire fields; every store includes both current and exact undo maps.
#[derive(JsonSerialize, JsonDeserialize)]
pub(crate) struct SnapshotSccpState {
    pub(super) sccp_parameters: Cell<Option<SccpParametersV1>>,
    pub(super) sccp_reset_nonce: Cell<Option<[u8; 32]>>,
    pub(super) sccp_committee_generations: snapshot_storage::SnapshotStorage,
    pub(super) sccp_committee_current: Cell<u64>,
    pub(super) sccp_forgery_offences: snapshot_storage::SnapshotStorage,
    pub(super) sccp_forgery_max_generation: Cell<Option<u64>>,
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
            store sccp_forgery_offences,
            cell sccp_forgery_max_generation,
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

impl SnapshotSccpState {
    /// Decode and validate every current/predecessor envelope before publishing any field.
    pub(super) fn restore(self, world: &mut World) -> Result<(), StateRestoreError> {
        validate_cell(&self.sccp_parameters, "sccp_parameters", valid_parameters)?;
        validate_cell(
            &self.sccp_reset_nonce,
            "sccp_reset_nonce",
            valid_reset_nonce,
        )?;
        validate_cell(&self.sccp_history, "sccp_history", valid_history)?;
        validate_cell(&self.sccp_anchor_open, "sccp_anchor_open", |anchors| {
            if anchors.len() <= 4096 {
                Ok(())
            } else {
                Err("an open anchor chunk exceeds 4096 entries".to_owned())
            }
        })?;
        let committee_generations = self
            .sccp_committee_generations
            .decode_generations(world.sccp_committee_generations.allocation_budget())?;
        let forgery_offences = self
            .sccp_forgery_offences
            .decode_forgery_offences(world.sccp_forgery_offences.allocation_budget())?;
        let max_current = *self.sccp_forgery_max_generation.view().get();
        let max_previous = *self.sccp_forgery_max_generation.predecessor_view().get();
        let snapshot = forgery_offences.snapshot();
        for (key, previous) in snapshot.revert_map().iter() {
            if previous
                .as_ref()
                .is_some_and(|id| snapshot.current().get(key) != Some(id))
            {
                return Err(invalid(
                    "sccp_forgery_offences",
                    "permanent offence was removed or rebound",
                )
                .into());
            }
        }
        let evidence = world.consensus_evidence.snapshot();
        // SCCP bodies are permanent; only the independent penalty metadata may change.
        for (id, old) in evidence.revert_map().iter() {
            if let Some(old) = old {
                if matches!(
                    old.evidence,
                    iroha_data_model::block::consensus::RecordedEvidenceV1::SccpForgery(_)
                ) && evidence
                    .current()
                    .get(id)
                    .is_none_or(|current| &**current != &**old)
                {
                    return Err(invalid(
                        "consensus_evidence",
                        "permanent SCCP evidence body was removed or rebound",
                    )
                    .into());
                }
            }
        }
        // Reconstruct both exact cuts without a copied graph or an intermediate map.
        let offence_at = |key: &sccp_forgery_custody::OffenceKey, previous: bool| {
            if previous {
                if let Some(old) = snapshot.revert_map().get(key) {
                    return old.as_ref();
                }
            }
            snapshot.current().get(key)
        };
        let evidence_at = |id: &Hash, previous: bool| {
            if previous {
                if let Some(old) = evidence.revert_map().get(id) {
                    return old.as_ref();
                }
            }
            evidence.current().get(id)
        };
        for previous in [false, true] {
            for key in snapshot
                .current()
                .iter()
                .map(|(key, _)| key)
                .chain(snapshot.revert_map().iter().map(|(key, _)| key))
            {
                let Some(id) = offence_at(key, previous) else {
                    continue;
                };
                let record = evidence_at(&Hash::prehashed(*id), previous).ok_or_else(|| {
                    invalid(
                        "sccp_forgery_offences",
                        "offence lacks its permanent evidence record in current/undo cut",
                    )
                })?;
                let iroha_data_model::block::consensus::RecordedEvidenceV1::SccpForgery(material) =
                    &record.evidence
                else {
                    return Err(invalid(
                        "sccp_forgery_offences",
                        "native evidence cannot back an SCCP offence",
                    )
                    .into());
                };
                let (generation, lane, validator) = &**key;
                if record.sccp_evidence_id() != Some(*id)
                    || material.generation != *generation
                    || !material
                        .offenders
                        .iter()
                        .any(|o| o.lane_id == *lane && o.validator == *validator)
                {
                    return Err(invalid(
                        "sccp_forgery_offences",
                        "offence/evidence original tuple differs",
                    )
                    .into());
                }
            }
            for id in evidence
                .current()
                .iter()
                .map(|(id, _)| id)
                .chain(evidence.revert_map().iter().map(|(id, _)| id))
            {
                let Some(record) = evidence_at(id, previous) else {
                    continue;
                };
                if let iroha_data_model::block::consensus::RecordedEvidenceV1::SccpForgery(
                    material,
                ) = &record.evidence
                {
                    let exact = record
                        .sccp_evidence_id()
                        .ok_or_else(|| invalid("consensus_evidence", "invalid SCCP identity"))?;
                    if *id != Hash::prehashed(exact) {
                        return Err(invalid("consensus_evidence", "SCCP record key differs").into());
                    }
                    for offender in &material.offenders {
                        let key = sccp_forgery_custody::OffenceKey::try_copy(
                            material.generation,
                            offender.lane_id,
                            &offender.validator,
                            world.sccp_forgery_offences.allocation_budget(),
                        )?;
                        if offence_at(&key, previous) != Some(&exact) {
                            return Err(invalid(
                                "sccp_forgery_offences",
                                "SCCP record lacks its exact permanent offence in current/undo cut",
                            )
                            .into());
                        }
                    }
                }
            }
        }
        drop(evidence);
        let current_max = snapshot
            .current()
            .iter()
            .map(|(key, _)| key.generation())
            .max();
        let previous_max = snapshot
            .current()
            .iter()
            .filter(|(key, _)| snapshot.revert_map().get(key).is_none())
            .map(|(key, _)| key.generation())
            .chain(
                snapshot
                    .revert_map()
                    .iter()
                    .filter_map(|(key, value)| value.as_ref().map(|_| key.generation())),
            )
            .max();
        if max_current != current_max || max_previous.unwrap_or(max_current) != previous_max {
            return Err(invalid(
                "sccp_forgery_max_generation",
                "maximum does not match permanent current/undo offences",
            )
            .into());
        }
        // Fund replacement scalar controls under the same original offence pool before publication.
        let forgery_max_generation = sccp_forgery_custody::initialize_max(
            max_current,
            max_previous,
            world.sccp_forgery_offences.allocation_budget(),
        )?;
        drop(snapshot);
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
        world.sccp_parameters = self.sccp_parameters;
        world.sccp_reset_nonce = self.sccp_reset_nonce;
        world.sccp_committee_generations = committee_generations;
        world.sccp_committee_current = self.sccp_committee_current;
        world.sccp_forgery_offences = forgery_offences;
        world.sccp_forgery_max_generation = forgery_max_generation;
        world.sccp_liability_clock = self.sccp_liability_clock;
        world.sccp_degraded_run = self.sccp_degraded_run;
        world.sccp_anchor_open = self.sccp_anchor_open;
        world.sccp_anchor_chunks = anchor_chunks;
        world.sccp_block_leaves = block_leaves;
        world.sccp_block_commitments = block_commitments;
        world.sccp_history = self.sccp_history;
        world.sccp_history_leaves = history_leaves;
        world.sccp_outbound_messages = outbound_messages;
        world.sccp_outbound_by_nonce = outbound_by_nonce;
        world.sccp_control_messages = control_messages;
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
