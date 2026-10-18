//! Refuse a new burn unless its original route, source horizon and recipient remain usable.

use super::*;
use iroha::data_model::{
    account::{AccountId, controller::AccountController, curve::CurveId},
    sccp::{light_client::SccpLightClientV1, registry::SccpRouteRevisionV1},
};
use iroha_crypto::Algorithm;
use iroha_sccp::light_client::{
    profile::SccpChainProfilesV1, proof::SccpLcSetDataV1,
    weak_subjectivity_deadline_ms_with_profiles,
};

const PROFILE_MARGIN_MS: u64 = 7 * 24 * 60 * 60 * 1000;

fn require_route(revision: &SccpRouteRevisionV1, forgery_max: Option<u64>) -> Result<()> {
    ensure!(
        matches!(
            revision.activation,
            SccpRouteActivationV1::Bidirectional | SccpRouteActivationV1::InboundOnly
        ),
        "burn requires a Bidirectional or InboundOnly revision"
    );
    ensure!(
        revision.quarantine.is_none() && !revision.forgery_held(forgery_max),
        "burn refused while the revision is quarantined or forgery-held"
    );
    Ok(())
}

fn require_horizon(
    client: &SccpLightClientV1,
    now_ms: u64,
    deadline_ms: u64,
    bound_ms: u64,
    supported_until_ms: Option<u64>,
) -> Result<()> {
    ensure!(!client.is_frozen(), "source light client is frozen");
    // Round up: one millisecond below the required quarter must never be accepted.
    let quarter = bound_ms / 4 + u64::from(!bound_ms.is_multiple_of(4));
    ensure!(
        bound_ms > 0
            && deadline_ms
                .checked_sub(now_ms)
                .is_some_and(|left| left >= quarter),
        "source light client has less than 25 percent of its weak-subjectivity bound left"
    );
    ensure!(
        supported_until_ms
            .and_then(|until| until.checked_sub(now_ms))
            .is_some_and(|left| left > PROFILE_MARGIN_MS),
        "source profile is unavailable or within seven days of its supported horizon"
    );
    Ok(())
}

fn require_controller(recipient: &[u8], capabilities: &norito::json::Value) -> Result<AccountId> {
    ensure!(
        recipient.len() <= 1024,
        "recipient exceeds the SCCP 1024-byte bound"
    );
    let address = AccountAddress::from_canonical_bytes(recipient)?;
    let account = address.to_account_id()?;
    ensure!(
        address.canonical_bytes()? == recipient,
        "recipient is not canonical"
    );
    let crypto = capabilities
        .get("crypto")
        .ok_or_else(|| eyre!("missing crypto admission"))?;
    let algorithms = crypto
        .get("sm")
        .and_then(|sm| sm.get("allowed_signing"))
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("missing signing admission"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| eyre!("malformed signing admission"))?
                .parse::<Algorithm>()
                .map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;
    let curves = crypto
        .get("curves")
        .and_then(|curves| curves.get("allowed_curve_ids"))
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("missing curve admission"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|id| u8::try_from(id).ok())
                .ok_or_else(|| eyre!("malformed curve admission"))
        })
        .collect::<Result<Vec<_>>>()?;
    let check = |key: &iroha_crypto::PublicKey| -> Result<()> {
        let algorithm = key.try_algorithm()?;
        // Match ordinary account admission, including its consensus BLS exception.
        if matches!(algorithm, Algorithm::BlsNormal | Algorithm::BlsSmall) {
            return Ok(());
        }
        ensure!(
            algorithms.contains(&algorithm),
            "recipient signing algorithm is not admitted"
        );
        let curve = CurveId::try_from_algorithm(algorithm)?;
        ensure!(
            curves.contains(&curve.as_u8()),
            "recipient curve is not admitted"
        );
        Ok(())
    };
    match account.controller() {
        AccountController::Single(key) => check(key)?,
        AccountController::Multisig(policy) => {
            for member in policy.members() {
                check(member.public_key())?;
            }
        }
    }
    Ok(account)
}

fn weak_subjectivity_bound(
    profiles: &SccpChainProfilesV1,
    client: &SccpLightClientV1,
    newest: &SccpLcConsensusSetV1,
) -> Result<u64> {
    if client.params.network != SccpNetworkV1::TonMainnet {
        return Ok(client.params.ws_bound_ms);
    }
    let SccpLcSetDataV1::Ton(epoch) = SccpLcSetDataV1::from_frame(&newest.set_bytes)? else {
        return Err(eyre!("TON light client retains another signing-set family"));
    };
    ensure!(
        u64::from(epoch.key_block_seqno) == newest.set_id,
        "TON signing set identity mismatch"
    );
    u64::from(epoch.stake_held_for)
        .checked_mul(1000)
        .and_then(|held| held.checked_sub(profiles.ton.freshness_margin_ms))
        .filter(|bound| *bound > 0)
        .ok_or_else(|| eyre!("TON retained stake does not cover its freshness margin"))
}

pub(super) fn preflight(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    revision: u32,
    recipient: &[u8],
) -> Result<Vec<SccpEvidenceItemV1>> {
    let capabilities = client.sccp().capabilities()?;
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("burn route is absent"))?;
    original.verify_route(network, &route)?;
    let revision = route
        .revisions
        .get(&revision)
        .ok_or_else(|| eyre!("burn revision is absent"))?;
    require_route(revision, original.forgery_max(&capabilities)?)?;
    let profiles = original.light_client_profiles(client)?;
    let detail = client.sccp().light_client(network)?;
    let sets = client.sccp().light_client_sets(network)?;
    let mut newest = sets
        .iter()
        .filter(|set| set.set_id == detail.light_client.head.latest_set_id);
    let newest_set = newest
        .next()
        .ok_or_else(|| eyre!("newest source signing set is absent"))?;
    ensure!(
        newest.next().is_none(),
        "duplicate newest source signing set"
    );
    let original_time =
        original.verify_burn_light_client(network, &detail.light_client, newest_set)?;
    let bound = weak_subjectivity_bound(&profiles, &detail.light_client, newest_set)?;
    let replay = LightClientReplayV1::new(
        &profiles,
        network,
        detail.light_client,
        vec![newest_set.clone()],
        vec![],
    );
    let deadline = weak_subjectivity_deadline_ms_with_profiles(&profiles, replay.state(), network)?;
    let now = wall_clock_ms().max(original_time);
    require_horizon(
        &detail.light_client,
        now,
        deadline,
        bound,
        profiles.supported_until_ms(network),
    )?;
    let admission = client.client().get_node_capabilities_json()?;
    require_controller(recipient, &admission)?;
    Ok(vec![
        flows::evidence("taira.original_burn_route", revision)?,
        flows::evidence("taira.original_burn_light_client", &detail.light_client)?,
        flows::evidence("taira.original_burn_signing_set", newest_set)?,
        flows::evidence("taira.burn_recipient_admission", &admission)?,
    ])
}

#[cfg(test)]
mod tests;
