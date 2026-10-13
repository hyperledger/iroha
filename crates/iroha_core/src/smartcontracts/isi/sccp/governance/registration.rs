//! Available native registration checks (§4.14.3 P1–P5), without a launch-gate bypass.
//!
//! The original opaque execution tip authenticates Global/NetworkId/I. Retained generations
//! authenticate the pin and every reachable successor; a valid shape alone never does.
//! P0 still depends on qualified Parliament and reconciliation. EVM P4 consumes the
//! embedded artifact lock; TON P3 requires the compiled minter/wallet/bucket references;
//! P5 reads the native offence publication's retained maximum.

use super::{Error, SccpRegisterRouteActionV1, refuse, store};
use crate::{
    smartcontracts::isi::sccp::generation_record::RetainedSccpGeneration,
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
    sumeragi::crypto::BlsCrypto,
};
use iroha_data_model::sccp::generation::SccpGenerationCauseV1;
use iroha_data_model::{
    NetworkId,
    block::consensus::SumeragiRootScope,
    sccp::{deployment::SccpCommitteePinV1, deployment::SccpDeploymentV1},
};
use iroha_sccp::v1::{
    evm_abi::ConstructorArgsV1,
    ton_cell::{TonMinterInitV1, locked_code_refs, minter_account_id},
};

// Fixed §3.1 constant, not a node-local setting or caller-supplied grace period.
const PIN_MARGIN_MS: u64 = 86_400_000;

struct OriginalIdentity {
    network: [u8; 32],
    instance: [u8; 32],
    parent_height: u64,
}

fn original_identity(view: &(impl StateReadOnly + ?Sized)) -> Result<OriginalIdentity, Error> {
    let tip = view
        .native_execution_tip()
        .ok_or_else(|| refuse("original committed execution tip is absent"))?;
    let parent_height =
        u64::try_from(view.height()).map_err(|_| refuse("committed journal height exceeds u64"))?;
    if tip.height() != parent_height
        || view
            .height()
            .checked_sub(1)
            .and_then(|index| view.block_hashes().get(index))
            != Some(&tip.iroha_hash())
        || view
            .block_hashes()
            .get(0)
            .map(|hash| NetworkId::from_genesis_hash(*hash))
            != Some(*view.network_id())
    {
        return Err(refuse("original tip, journal and NetworkId do not match"));
    }
    let scope = tip.root_scope();
    if scope != SumeragiRootScope::Global {
        return Err(refuse("RegisterRoute requires the original Global root"));
    }
    let instance = scope
        .instance_id(
            &BlsCrypto::new(),
            *view.network_id(),
            view.chain_id().as_str(),
        )
        .map_err(|_| refuse("original consensus instance is invalid"))?
        .0;
    Ok(OriginalIdentity {
        network: *view.network_id().as_bytes(),
        instance,
        parent_height,
    })
}

/// Validate the available checks without changing any registry, nonce, leaf or event.
pub(super) fn validate_available(
    stx: &StateTransaction<'_, '_>,
    register: &SccpRegisterRouteActionV1,
) -> Result<(), Error> {
    let identity = original_identity(stx)?;
    let world = &*stx.world;
    let params = store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP does not exist on this network"))?;
    let record = retained_pin(
        world,
        &register.initial_committee,
        stx.block_unix_timestamp_ms(),
        params.committee_heartbeat_ms,
        identity.parent_height,
    )?;
    forgery_floor(world, register.initial_committee.generation)?;
    deployment(register, record, &identity)
}

fn forgery_floor(world: &(impl WorldReadOnly + ?Sized), generation: u64) -> Result<(), Error> {
    if !cfg!(all(test, sumeragi_core_mutation = "HC283"))
        && store::forgery_max_generation(world).is_some_and(|maximum| maximum >= generation)
    {
        return Err(refuse(
            "pinned generation does not exceed the retained forgery maximum",
        ));
    }
    Ok(())
}

fn retained_pin<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
    pin: &SccpCommitteePinV1,
    now_ms: u64,
    heartbeat_ms: u64,
    parent_height: u64,
) -> Result<&'a RetainedSccpGeneration, Error> {
    pin.validate_shape()
        .map_err(|_| refuse("native committee pin shape is invalid"))?;
    let current = *store::committee_current::get(world);
    if pin.generation > current {
        return Err(refuse("pinned generation is beyond the current generation"));
    }
    let pinned = store::committee_generations::get(world, &pin.generation)
        .ok_or_else(|| refuse("pinned generation is not retained"))?;
    if (pin.committee_root, pin.start_height, pin.until_ms)
        != (
            pinned.committee_root,
            pinned.start_height,
            pinned.deadline_ms,
        )
    {
        return Err(refuse(
            "native committee pin differs from its retained generation",
        ));
    }
    let required_until = now_ms
        .checked_add(heartbeat_ms)
        .and_then(|n| n.checked_add(PIN_MARGIN_MS))
        .ok_or_else(|| refuse("registration deadline requirement overflows"))?;
    let next_height = parent_height
        .checked_add(1)
        .ok_or_else(|| refuse("registration height overflows"))?;
    let mut previous: Option<&RetainedSccpGeneration> = None;
    // Iterate retained entries, not a caller-controlled numeric gap. Missing ids refuse.
    for (key, record) in store::committee_generations::range(world, pin.generation..=current) {
        if *key != record.generation
            || !record.is_well_formed()
            || record.start_height > next_height
            || record.members.iter().any(Option::is_none)
            || record
                .keys
                .iter()
                .any(|key| !iroha_crypto::bls::consensus::key_validate(key))
        {
            return Err(refuse(
                "registration generation is invalid or has unresolved members",
            ));
        }
        if record.deadline_ms < required_until {
            return Err(refuse(
                "an intervening generation expires before the registration margin",
            ));
        }
        if let Some(old) = previous {
            let end = old
                .end
                .as_ref()
                .ok_or_else(|| refuse("retained handoff is absent"))?;
            if old.generation.checked_add(1) != Some(record.generation)
                || end.end_height.checked_add(1) != Some(record.start_height)
                || end.end_height > parent_height
                || end.end_timestamp_ms != record.start_timestamp_ms
                || end.next_committee_root != record.committee_root
                || end.successor_validity_ms != record.validity_ms
                || !matches!(
                    record.cause,
                    SccpGenerationCauseV1::KeyChange | SccpGenerationCauseV1::Heartbeat
                )
            {
                return Err(refuse(
                    "the pin has no continuous genuine handoff path to current",
                ));
            }
        }
        previous = Some(record);
    }
    if previous.is_none_or(|last| last.generation != current || last.end.is_some()) {
        return Err(refuse("the current generation is absent or already ended"));
    }
    Ok(pinned)
}

fn deployment(
    register: &SccpRegisterRouteActionV1,
    pinned: &RetainedSccpGeneration,
    identity: &OriginalIdentity,
) -> Result<(), Error> {
    match register.deployment {
        SccpDeploymentV1::Ton(ton) => {
            if !cfg!(all(test, sumeragi_core_mutation = "HC326"))
                && [ton.minter_code, ton.wallet_code, ton.bucket_code] != locked_code_refs()
            {
                return Err(refuse(
                    "TON code references differ from the locked artifacts",
                ));
            }
            let pin = register.initial_committee;
            let init = TonMinterInitV1 {
                taira_network_id: identity.network,
                consensus_instance: identity.instance,
                route_revision: register.revision,
                max_supply: register.max_wrapped_supply,
                pin,
                keys: pinned.keys.clone(),
                wallet_code: ton.wallet_code,
                bucket_code: ton.bucket_code,
            };
            let expected = minter_account_id(&init, ton.minter_code)
                .map_err(|_| refuse("native TON StateInit cannot be constructed"))?;
            if expected != ton.master_account {
                return Err(refuse(
                    "TON master_account differs from the exact native StateInit",
                ));
            }
            Ok(())
        }
        SccpDeploymentV1::Evm(evm) => {
            let expected = ConstructorArgsV1 {
                taira_network_id: identity.network,
                consensus_instance: identity.instance,
                network: register.network,
                route_revision: register.revision,
                max_wrapped_supply: register.max_wrapped_supply,
                pin: register.initial_committee,
            }
            .address();
            if !cfg!(all(test, sumeragi_core_mutation = "HC276")) && expected != evm.address {
                return Err(refuse(
                    "EVM address differs from the exact locked CREATE2 deployment",
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "registration/tests.rs"]
mod tests;
