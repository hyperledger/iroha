//! Public bounded discovery of application-independent deterministic game sessions.
use crate::{Error, SharedAppState};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use iroha_core::state::{StateReadOnly, WorldReadOnly};
use iroha_crypto::Hash;
use mv::storage::StorageReadOnly;
/// Stable exclusive session-id pagination.
#[derive(Default, Debug, crate::json_macros::JsonDeserialize)]
pub struct GameListParams {
    /// Exclusive canonical session hash cursor.
    pub cursor: Option<String>,
    /// Optional exact application filter; filtering does not expand the scan budget.
    pub application_id: Option<Hash>,
    /// Optional exact compiled execution profile filter.
    pub profile_id: Option<Hash>,
}
/// Local transport admission only; this does not authenticate remote peers or qualify a proof.
#[derive(Clone, Copy, Debug)]
struct ExecutionTransportLimits {
    connect_enabled: bool,
    torii_body: u64,
    transaction: u64,
    decompressed_transaction: u64,
    connect_frame: u64,
    connect_buffer: u64,
    connect_p2p: u64,
    transaction_gossip: u64,
}
impl ExecutionTransportLimits {
    fn ready(self) -> bool {
        // The typed execution wallet corridor reserves this framing budget around
        // its bounded canonical instruction payload. P2P includes larger relay and
        // queue-plan wrappers; the explicit release overlay budgets eight MiB.
        let framed =
            iroha_data_model::execution_proofs::EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1 as u64 + 4096;
        let peer = 8 * 1024 * 1024;
        self.connect_enabled
            && self.torii_body >= framed
            && self.transaction >= framed
            && self.decompressed_transaction >= framed
            && self.connect_frame >= framed
            && self.connect_buffer >= self.connect_frame
            && self.connect_p2p >= peer
            && self.transaction_gossip >= peer
    }
}
fn execution_transport_ready(app: &SharedAppState) -> bool {
    #[cfg(all(feature = "app_api", feature = "connect"))]
    {
        let Some(network) = &app.p2p else {
            return false;
        };
        let (frame, buffer) = app.connect_bus.frame_limits();
        let view = app.state.view();
        let transaction = view.world().parameters().transaction();
        ExecutionTransportLimits {
            connect_enabled: app.connect_enabled,
            torii_body: app.transaction_max_content_len as u64,
            transaction: transaction.max_tx_bytes().get(),
            decompressed_transaction: transaction.max_decompressed_bytes().get(),
            connect_frame: frame as u64,
            connect_buffer: buffer as u64,
            connect_p2p: network
                .outbound_topic_frame_cap(iroha_p2p::network::message::Topic::Connect)
                as u64,
            transaction_gossip: network
                .outbound_topic_frame_cap(iroha_p2p::network::message::Topic::TxGossip)
                as u64,
        }
        .ready()
    }
    #[cfg(not(all(feature = "app_api", feature = "connect")))]
    {
        let _ = app;
        false
    }
}
/// Compiled application profiles and generic lifecycle limits bound to this network.
pub fn capabilities(app: &SharedAppState) -> Response {
    let transport_ready = execution_transport_ready(app);
    let view = app.state.view();
    let profiles = iroha_core_privacy::execution_proofs::compiled_execution_profiles_v1();
    crate::utils::JsonBody(norito::json!({
        "version":1,"current_height":(view.height().to_string()),"network_id":(view.network_id()),
        "fee_asset_id":(view.nexus().fees.fee_asset_id),
        "enabled":true,"native_game_sessions":true,"profiles":profiles,
        "execution_transport_ready":transport_ready,
        "max_participants":32,"max_input_bytes":4096,"max_participant_data_bytes":4096,
        "max_application_parameter_bytes":65536,"max_batch_ticks":256,"max_ticks":1000000,"max_batches":4096,"max_retained_input_bytes":4194304,
        "wallet_funds_required_only_for_entry":true,"stake_balance_scope":"Global","payout_claims":true,"max_item_stakes_per_slot":1,"item_tie_policy":"return_to_original_owners",
        "max_resources_per_slot":(iroha_data_model::game_resources::GAME_MAX_RESOURCES_PER_PARTICIPANT_V1),
        "max_resource_records":(iroha_data_model::game_resources::GAME_MAX_RESOURCE_RECORDS_V1),
        "resource_return_policy":"return_to_original_owner_at_terminal"
    })).into_response()
}
/// A direct session record is node evidence until ledger finality is authenticated.
pub fn get(app: &SharedAppState, id: &str) -> Result<Response, Error> {
    let id: Hash = id
        .parse()
        .map_err(|_| crate::routing::conversion_error("invalid session hash".into()))?;
    let view = app.state.view();
    let Some(session) = view.world().game_sessions().get(&id) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    Ok(crate::utils::JsonBody(session.clone()).into_response())
}
/// One compact receipt supplies the height and canonical proof-envelope commitment.
pub fn verification(app: &SharedAppState, id: &str) -> Result<Response, Error> {
    let id: Hash = id
        .parse()
        .map_err(|_| crate::routing::conversion_error("invalid verification hash".into()))?;
    let view = app.state.view();
    let Some(receipt) = view.world().execution_proof_verifications().get(&id) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    Ok(crate::utils::JsonBody(*receipt).into_response())
}
/// Scan at most 128 state keys and return at most 32 public summaries.
pub fn list(app: &SharedAppState, params: GameListParams) -> Result<Response, Error> {
    let cursor = params
        .cursor
        .map(|s| {
            s.parse::<Hash>()
                .map_err(|_| crate::routing::conversion_error("invalid session cursor".into()))
        })
        .transpose()?;
    let view = app.state.view();
    let mut rows = Vec::new();
    let mut next = None;
    let mut more = false;
    for (scanned, (id, session)) in view
        .world()
        .game_sessions()
        .range((
            cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
            std::ops::Bound::Unbounded,
        ))
        .take(129)
        .enumerate()
    {
        if scanned == 128 || rows.len() == 32 {
            more = true;
            break;
        }
        next = Some(*id);
        if params
            .application_id
            .is_some_and(|id| id != session.manifest.application_id)
            || params.profile_id.is_some_and(|id| id != session.profile_id)
        {
            continue;
        }
        if !matches!(
            session.manifest.access,
            iroha_data_model::game::GameAccessV1::Public
        ) {
            continue;
        }
        rows.push(norito::json!({
            "session_id": id,
            "manifest": (session.manifest),
            "stake": (session.stake),
            "payout_scale": (session.payout_scale),
            "liability": (session.liability),
            "payout_claims": (session.payout_claims),
            "item_stakes": (session.item_stakes),
            "resources": (session.resources),
            "verification_id": (session.verification_id),
            "terminal_at_height": (session.terminal_at_height.map(|height| height.to_string())),
            "asset_definition": (session.asset_definition),
            "participants": (session.participants),
            "phase": (session.phase),
            "revision": (session.revision),
            "deadline_height": (session.deadline_height),
            "result": (session.result),
        }));
    }
    Ok(crate::utils::JsonBody(norito::json!({"version":1,"network_id":(view.network_id()),"items":rows,"next_cursor":(if more {next} else {None})})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_transport_readiness_requires_every_local_corridor_bound() {
        let framed =
            iroha_data_model::execution_proofs::EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1 as u64 + 4096;
        let ready = ExecutionTransportLimits {
            connect_enabled: true,
            torii_body: framed,
            transaction: framed,
            decompressed_transaction: framed,
            connect_frame: framed,
            connect_buffer: framed,
            connect_p2p: 8 * 1024 * 1024,
            transaction_gossip: 8 * 1024 * 1024,
        };
        assert!(ready.ready());
        for index in 0..8 {
            let mut altered = ready;
            match index {
                0 => altered.connect_enabled = false,
                1 => altered.torii_body -= 1,
                2 => altered.transaction -= 1,
                3 => altered.decompressed_transaction -= 1,
                4 => altered.connect_frame -= 1,
                5 => altered.connect_buffer -= 1,
                6 => altered.connect_p2p -= 1,
                7 => altered.transaction_gossip -= 1,
                _ => unreachable!(),
            }
            assert!(!altered.ready(), "bound {index} must fail closed");
        }
        let ordinary_defaults = ExecutionTransportLimits {
            connect_frame: 64_000,
            connect_buffer: 262_144,
            connect_p2p: 131_072,
            transaction_gossip: 262_144,
            ..ready
        };
        assert!(!ordinary_defaults.ready());
    }
}
