//! Funded light-client metadata with original retained validator-set custody.

use super::*;
use crate::smartcontracts::isi::sccp::{
    light_client_set::RetainedSccpLcSet,
    light_clients::{WorldLightClientView, is_usable},
    read::{coalition, views},
};
use iroha_data_model::sccp::light_client::SccpLightClientV1;
use iroha_sccp::{
    api,
    light_client::{profile::SccpLcProfileCatalogV1, state::is_permanent_checkpoint},
};

/// Original installed clients under a caller-funded scalar vector.
/// # Errors
/// Preserves request budget, stop and deadline refusal.
pub fn clients(
    view: &(impl StateReadOnly + ?Sized),
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Vec<SccpLightClientV1>>> {
    deadline_check(control)?;
    let charge = budget.try_reserve_bytes(3 * size_of::<SccpLightClientV1>())?;
    let mut data = Vec::new();
    data.try_reserve_exact(3)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    for (_, client) in store::light_clients::iter(view.world()) {
        deadline_check(control)?;
        if data.len() == 3 {
            return Err(SccpNativeReadError::Invalid(
                "external light-client cardinality",
            ));
        }
        data.push(*client);
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Share original charged validator graphs and fund only the exact response handle vector.
/// # Errors
/// Preserves original request budget, cancellation and deadline refusal.
pub fn sets(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Vec<RetainedSccpLcSet>>> {
    deadline_check(control)?;
    let world = view.world();
    let bounds = (network, 0)..=(network, u64::MAX);
    let mut count = 0_usize;
    for _ in store::light_client_sets::range(world, bounds.clone()) {
        deadline_check(control)?;
        count = count
            .checked_add(1)
            .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    }
    let bytes = count
        .checked_mul(size_of::<RetainedSccpLcSet>())
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let charge = budget.try_reserve_bytes(bytes)?;
    let mut data = Vec::new();
    data.try_reserve_exact(count)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    for (_, record) in store::light_client_sets::range(world, bounds) {
        deadline_check(control)?;
        if data.len() == count {
            return Err(SccpNativeReadError::Unavailable(
                "consensus-set source changed",
            ));
        }
        data.push(record.clone());
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Describe a client from original scalar records and deadline-checked retained indices.
/// # Errors
/// Preserves missing source, budget, cancellation and deadline refusal.
pub fn detail(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<api::SccpLightClientDetailV1>> {
    deadline_check(control)?;
    let world = view.world();
    let light_client = *store::light_clients::get(world, &network)
        .ok_or(SccpNativeReadError::NotFound("light client"))?;
    let charge = budget.try_reserve_bytes(size_of::<api::SccpLightClientDetailV1>())?;
    let bounds = (network, 0)..=(network, u64::MAX);
    let mut sets = api::SccpLcSetsSummaryV1::default();
    for ((_, set_id), _) in store::light_client_sets::range(world, bounds.clone()) {
        deadline_check(control)?;
        sets.count = sets
            .count
            .checked_add(1)
            .ok_or(SccpNativeReadError::Invalid("set count"))?;
        sets.oldest_set_id.get_or_insert(*set_id);
        sets.latest_set_id = Some(*set_id);
    }
    let mut checkpoints = api::SccpLcCheckpointsSummaryV1::default();
    for ((_, height), _) in store::light_client_checkpoints::range(world, bounds.clone()) {
        deadline_check(control)?;
        checkpoints.count = checkpoints
            .count
            .checked_add(1)
            .ok_or(SccpNativeReadError::Invalid("checkpoint count"))?;
        checkpoints.lowest_source_height.get_or_insert(*height);
        checkpoints.highest_source_height = Some(*height);
    }
    for _ in store::light_client_stride_index::range(world, bounds) {
        deadline_check(control)?;
        checkpoints.permanent_buckets = checkpoints
            .permanent_buckets
            .checked_add(1)
            .ok_or(SccpNativeReadError::Invalid("bucket count"))?;
    }
    let catalog = SccpLcProfileCatalogV1::compiled();
    let active = coalition::active_profiles(view, control)?;
    let profiles = active.get(network).and_then(|profile| {
        catalog
            .resolve(&catalog.genesis().with(network, profile))
            .ok()
    });
    let now_ms = view.authenticated_query_ledger_time_ms();
    let data = api::SccpLightClientDetailV1 {
        light_client,
        usable: profiles
            .as_ref()
            .zip(now_ms)
            .is_some_and(|(profiles, time)| is_usable(world, profiles, network, time)),
        weak_subjectivity_deadline_ms: profiles.as_ref().and_then(|profiles| {
            iroha_sccp::light_client::weak_subjectivity_deadline_ms_with_profiles(
                profiles,
                &WorldLightClientView(world),
                network,
            )
            .ok()
        }),
        supported_until_ms: profiles.and_then(|profiles| profiles.supported_until_ms(network)),
        sets,
        checkpoints,
    };
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Select original covering checkpoints without copying any graph or scanning after refusal.
/// # Errors
/// Preserves absence/pruning, budget, cancellation and deadline refusal.
pub fn checkpoints(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    covering: u64,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<api::SccpLcCheckpointCoverV1>> {
    deadline_check(control)?;
    let world = view.world();
    let client = store::light_clients::get(world, &network)
        .ok_or(SccpNativeReadError::NotFound("light client"))?;
    let head = client.head.latest_finalized;
    let stride = client.params.checkpoint_stride;
    let charge = budget.try_reserve_bytes(size_of::<api::SccpLcCheckpointCoverV1>())?;
    let entry = |checkpoint: &iroha_data_model::sccp::light_client::SccpLcCheckpointV1| {
        let lowest = checkpoint
            .data
            .source_height
            .checked_div(stride)
            .and_then(|bucket| store::light_client_stride_index::get(world, &(network, bucket)))
            .copied();
        api::SccpLcCheckpointEntryV1 {
            checkpoint: *checkpoint,
            permanent: is_permanent_checkpoint(network, checkpoint, stride, lowest),
        }
    };
    let mut retained =
        store::light_client_checkpoints::range(world, (network, covering)..=(network, u64::MAX));
    let nearest = retained
        .next()
        .map(|(_, checkpoint)| entry(checkpoint))
        .ok_or_else(|| {
            if head.source_height >= covering {
                SccpNativeReadError::Pruned("covering checkpoint")
            } else {
                SccpNativeReadError::NotFound("source height not finalized")
            }
        })?;
    let mut nearest_permanent = nearest.permanent.then_some(nearest);
    if nearest_permanent.is_none() {
        let mut by_stride = None;
        if let Some(bucket) = covering.checked_div(stride) {
            for (_, height) in store::light_client_stride_index::range(
                world,
                (network, bucket)..=(network, u64::MAX),
            ) {
                deadline_check(control)?;
                if *height < covering {
                    continue;
                }
                by_stride = store::light_client_checkpoints::get(world, &(network, *height))
                    .map(entry)
                    .filter(|entry| entry.permanent);
                break;
            }
        }
        for (_, checkpoint) in retained.take(views::MAX_CHECKPOINT_SCAN) {
            deadline_check(control)?;
            if by_stride.is_some_and(|bound| {
                checkpoint.data.source_height >= bound.checkpoint.data.source_height
            }) {
                break;
            }
            let candidate = entry(checkpoint);
            if candidate.permanent {
                nearest_permanent = Some(candidate);
                break;
            }
        }
        nearest_permanent = nearest_permanent.or(by_stride);
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: api::SccpLcCheckpointCoverV1 {
            network,
            covering,
            head,
            nearest,
            nearest_permanent,
        },
        _charge: charge,
    })
}
