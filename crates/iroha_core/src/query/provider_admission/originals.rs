//! Original provider transport intent from the actual signed genesis initializer.
//!
//! This works before H2 and deliberately authenticates no genesis execution, admission head,
//! account permission or live transport. All current uses need independent certified discovery.

use super::ProviderAdmissionErrorV1;
use crate::{
    state::StateReadOnly,
    sumeragi::certified_chain::{bounded_native_carrier_extent, bounded_signed_genesis},
};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer};
use iroha_data_model::{
    account::AccountId,
    block::consensus::SumeragiRootScope,
    isi::sorafs::InitializeSorafsProviderAdmissionV1,
    sorafs::provider_admission::governance::{
        PROVIDER_ADMISSION_GENESIS_MAX_PROVIDERS_V1, decode_frame,
    },
    transaction::Executable,
};
use sorafs_manifest::provider_admission::ProviderAdmissionGenesisMaterialV1;
use std::alloc::Layout;

/// Borrow the bounded original provider intents from one unique signed genesis initializer.
///
/// The native State independently supplies genesis, chain and network identity. The signed
/// body and its initializer are authenticated; the unsigned genesis result is not used as
/// execution authority. Returning these originals confers neither current admission nor
/// account-read permission, and remains valid as original intent after later rotations.
/// # Errors
/// Missing/ambiguous initializer, foreign genesis, non-Global scope, invalid canonical material,
/// duplicate/unordered providers or an original allocation refusal. This makes no HTTP request.
pub fn with_genesis_provider_admission_originals_v1<R>(
    view: &impl StateReadOnly,
    maximum_providers: usize,
    budget: &AllocationBudget,
    consume: impl FnOnce(
        &[(AccountId, ProviderAdmissionGenesisMaterialV1)],
    ) -> Result<R, ProviderAdmissionErrorV1>,
) -> Result<R, ProviderAdmissionErrorV1> {
    struct Originals {
        values: ChargedBuffer<(AccountId, ProviderAdmissionGenesisMaterialV1)>,
        charges: ChargedBuffer<AllocationCharge>,
    }
    let invalid = ProviderAdmissionErrorV1;
    if maximum_providers == 0
        || maximum_providers > PROVIDER_ADMISSION_GENESIS_MAX_PROVIDERS_V1
        || view.block_hashes().is_empty()
        || view
            .kura()
            .exact_durable_blocks_count()
            .map_err(|_| invalid)?
            != view.block_hashes().len()
    {
        return Err(invalid);
    }
    // Preserve signed-body authentication through the sole native owner, with no result-only
    // genesis execution claim. Prepay the original nested decode envelope before acquisition.
    let extent = bounded_native_carrier_extent(
        view,
        1,
        iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
    )
    .map_err(|_| invalid)?;
    let limits = norito::canonical_decode_limits(extent);
    let layout = Layout::array::<u8>(
        limits
            .max_total_allocated_bytes()
            .checked_mul(2)
            .ok_or(invalid)?,
    )
    .map_err(|_| invalid)?;
    let _genesis_decode = budget
        .try_reserve(layout)
        .map_err(|_| invalid)?
        .try_split(layout)
        .map_err(|_| invalid)?;
    let genesis =
        norito::with_decode_limits_scope(limits, || bounded_signed_genesis(view, extent, budget))
            .map_err(|_| invalid)?;
    let metadata = iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
        .map_err(|_| invalid)?;
    if metadata.sumeragi_context.root_scope != SumeragiRootScope::Global {
        return Err(invalid);
    }
    let mut selected = None;
    for transaction in genesis.external_transactions() {
        // The genesis owner verifies every signature; this explicit check preserves the
        // direct external initializer's own authorization before its fields are selected.
        if transaction.network_id().is_some() {
            return Err(invalid);
        }
        transaction.verify_signature().map_err(|_| invalid)?;
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(invalid);
        };
        for instruction in instructions {
            if let Some(initializer) = instruction
                .as_any()
                .downcast_ref::<InitializeSorafsProviderAdmissionV1>()
            {
                if selected.replace(initializer).is_some() {
                    return Err(invalid);
                }
            }
        }
    }
    let initializer = selected.ok_or(invalid)?;
    if initializer.providers.is_empty() || initializer.providers.len() > maximum_providers {
        return Err(invalid);
    }
    initializer
        .council
        .bind(*view.network_id().as_bytes())
        .map_err(|_| invalid)?;
    let count = initializer.providers.len();
    // Actual tuple backing and every decoded material retain their original charges through
    // the borrowing callback. The callback must separately admit any copies it retains.
    let mut originals = Originals {
        values: ChargedBuffer::new(count, budget).map_err(|_| invalid)?,
        charges: ChargedBuffer::new(count, budget).map_err(|_| invalid)?,
    };
    let mut previous = None;
    for entry in &initializer.providers {
        let limits = norito::canonical_decode_limits(entry.material.len());
        let account = norito::canonical_frame_len(&entry.owner).map_err(|_| invalid)?;
        let bytes = limits
            .max_total_allocated_bytes()
            .checked_add(account)
            .ok_or(invalid)?;
        let layout = Layout::array::<u8>(bytes).map_err(|_| invalid)?;
        let charge = budget
            .try_reserve(layout)
            .map_err(|_| invalid)?
            .try_split(layout)
            .map_err(|_| invalid)?;
        let material: ProviderAdmissionGenesisMaterialV1 =
            norito::with_decode_limits_scope(limits, || decode_frame(&entry.material))
                .map_err(|_| invalid)?;
        material.validate().map_err(|_| invalid)?;
        let provider = material.proposal.provider_id;
        if provider == [0; 32] || previous.is_some_and(|previous| previous >= provider) {
            return Err(invalid);
        }
        previous = Some(provider);
        originals.charges.push_reserved(charge);
        originals
            .values
            .push_reserved((entry.owner.clone(), material));
    }
    consume(originals.values.as_slice())
}

#[cfg(test)]
mod tests;
