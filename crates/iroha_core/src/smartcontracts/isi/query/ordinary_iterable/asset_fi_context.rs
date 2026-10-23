//! Owner-scoped current FI candidates through the existing ordinary query owner.
use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError,
    smartcontracts::{code, isi::asset_fi_context as context},
    state::asset_context_keys as keys,
};
use iroha_data_model::{
    asset::{
        AssetBalancePolicy,
        fi_context::{AssetFiContextSnapshotV1, AssetFiControllerBindingV1},
    },
    parameter::system::consensus_metadata,
    query::asset_fi_context::FindAssetFiContextV1,
};
use iroha_model_base::state_path::StatePath;

fn decode_error(error: norito::core::DecodeAttemptError) -> QueryAttemptError {
    match error.into_local_refusal() {
        Ok(original) => ExecutionAttemptError::Deferred(original.into()),
        Err(error) if error.error().is_decode_resource_limit() => Error::CapacityLimit.into(),
        Err(_) => Error::Conversion("invalid canonical native FI context".into()).into(),
    }
}
fn native_error(
    error: ExecutionAttemptError<iroha_data_model::isi::error::InstructionExecutionError>,
) -> QueryAttemptError {
    match error {
        ExecutionAttemptError::Deferred(original) => ExecutionAttemptError::Deferred(original),
        ExecutionAttemptError::Rejected(error) => Error::Conversion(error.to_string()).into(),
    }
}
fn canonical<T>(
    operation: impl FnOnce() -> Result<T, norito::Error>,
) -> Result<T, QueryAttemptError> {
    norito::core::classify_decode_attempt(operation).map_err(decode_error)
}
fn measured<T>(
    graph: &mut RetainedDecodeBudget,
    maximum: usize,
    operation: impl FnOnce() -> Result<T, QueryAttemptError>,
) -> Result<T, QueryAttemptError> {
    let elements = maximum.checked_mul(8).ok_or(Error::CapacityLimit)?;
    let scope = norito::DecodeLimits::new(elements, maximum, elements, graph.next_limit()?, 64);
    let (result, usage) = norito::core::with_decode_limits_measured(scope, operation);
    let value = result?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    Ok(value)
}
fn account_text(
    account: &AccountId,
    graph: &mut RetainedDecodeBudget,
    maximum: usize,
) -> Result<String, QueryAttemptError> {
    measured(graph, maximum, || {
        canonical(|| {
            norito::json::to_json_bounded(account, maximum)
                .map_err(norito::json::BoundedJsonError::into_core_error)
        })
    })
}
fn literal(json: &str) -> Result<&str, Error> {
    json.strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .filter(|text| !text.contains(['"', '\\']))
        .ok_or_else(|| Error::Conversion("invalid native I105 account text".into()))
}
fn point<T: NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>>(
    state: &impl StateReadOnly,
    key: &StatePath,
    graph: &mut RetainedDecodeBudget,
    maximum: usize,
    stats: &mut QueryExecutionStats,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<Option<T>, QueryAttemptError> {
    stats.record_preflighted_item(
        limits
            .max_source_item_bytes()
            .checked_mul(3)
            .ok_or(Error::CapacityLimit)?,
        Some(limits.execution_budget()),
    )?;
    let Some(bytes) = state.world().smart_contract_state().get(key) else {
        return Ok(None);
    };
    if bytes.len() > maximum {
        return Err(Error::CapacityLimit.into());
    }
    measured(graph, maximum, || {
        canonical(|| norito::decode_canonical(bytes))
    })
    .map(Some)
}

pub(super) fn collect(
    query: &FindAssetFiContextV1,
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<
    (
        ExactOwnedRows<AssetFiContextSnapshotV1>,
        QueryExecutionStats,
    ),
    QueryAttemptError,
> {
    if mode != OrdinaryCursorMode::Ephemeral
        || params.pagination.offset_value() != 0
        || params.sorting.sort_by_metadata_key.is_some()
    {
        return Err(Error::Conversion(
            "FI context requires one unsorted ephemeral complete lookup".into(),
        )
        .into());
    }
    let (_, maximum, work) = trigger_source_limits(params, mode, limits)?;
    let (mut graph, slots) =
        RetainedDecodeBudget::new::<AssetFiContextSnapshotV1>(1, limits.max_source_item_bytes())?;
    let mut stats = QueryExecutionStats::default();
    // Admission precedes target work and every definition/account/incarnation lookup.
    for _ in 0..4 {
        stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
    }
    if canonical(|| norito::canonical_frame_len(&query.target))? > maximum {
        return Err(Error::CapacityLimit.into());
    }
    let selected = context::target_selection(&query.target)
        .map_err(|error| Error::Conversion(error.to_string()))?;
    query
        .expected_incarnation
        .validate()
        .map_err(|_| Error::Conversion("invalid expected FI incarnation".into()))?;
    if query.expected_uid == [0; 32] {
        return Err(Error::Conversion("FI context UID is zero".into()).into());
    }
    let world = state.world();
    let definition = world
        .asset_definitions()
        .get(selected.asset_definition_id)
        .ok_or_else(|| Error::Conversion("FI context asset definition is unavailable".into()))?;
    if definition.balance_scope_policy() != AssetBalancePolicy::Global {
        return Err(Error::Conversion("FI context requires a Global definition".into()).into());
    }
    if world.accounts().get(selected.account_id).is_none() {
        return Err(Error::Conversion("FI context wallet is unavailable".into()).into());
    }
    let incarnation = world
        .axt_asset_incarnations()
        .get(selected.asset_definition_id)
        .copied();
    if incarnation.as_ref() != Some(&query.expected_incarnation) {
        return Err(
            Error::Conversion("FI context requires the exact live incarnation".into()).into(),
        );
    }
    // Source-owned canonical account rendering and all retained keys are fallible.
    let account_json = account_text(selected.account_id, &mut graph, maximum)?;
    let fi_json = account_text(selected.fi_account_id, &mut graph, maximum)?;
    let account = literal(&account_json)?;
    let fi = literal(&fi_json)?;
    let key = measured(&mut graph, maximum, || {
        canonical(|| keys::uid_binding(selected.asset_definition_id, account))
    })?;
    let binding = point(state, &key, &mut graph, maximum, &mut stats, limits)?;
    let key = measured(&mut graph, maximum, || {
        canonical(|| keys::uid_policy(selected.asset_definition_id, &query.expected_uid))
    })?;
    let policy = point(state, &key, &mut graph, maximum, &mut stats, limits)?;
    let key = measured(&mut graph, maximum, || {
        canonical(|| keys::fi(selected.asset_definition_id, fi))
    })?;
    let eligibility = point(state, &key, &mut graph, maximum, &mut stats, limits)?;
    let key = measured(&mut graph, maximum, || {
        canonical(|| {
            keys::attestation(
                selected.asset_definition_id,
                account,
                fi,
                selected.reference_digest,
            )
        })
    })?;
    let attestation = point(state, &key, &mut graph, maximum, &mut stats, limits)?;
    let key = measured(&mut graph, maximum, || {
        canonical(|| keys::link(selected.asset_definition_id, account))
    })?;
    let link = point(state, &key, &mut graph, maximum, &mut stats, limits)?;
    drop(account_json);
    drop(fi_json);
    let source = context::ContextRows {
        binding,
        policy,
        fi: eligibility,
        attestation,
        link,
    };
    let controller = if let Some(address) = context::selected_controller(&selected, &source) {
        // The narrow native adapter retains root/lifecycle authority. The query
        // prepays its fixed registry lookups and bounds their borrowed frames.
        for _ in 0..8 {
            stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
        }
        if let Some(binding) = world.contract_subject_bindings().get(address) {
            if canonical(|| norito::canonical_frame_len(binding))? > maximum {
                return Err(Error::CapacityLimit.into());
            }
        }
        let parameters = world.parameters();
        if let Some(metadata) = parameters
            .custom()
            .get(&consensus_metadata::handshake_meta_id())
        {
            if metadata.payload().get().as_str().len() > maximum {
                return Err(Error::CapacityLimit.into());
            }
        }
        measured(&mut graph, maximum, || {
            let subject = match code::try_borrow_active_contract_subject_for_observation(
                world,
                address,
                u64::try_from(state.height()).map_err(|_| Error::CapacityLimit)?,
                |bytes| {
                    stats.record_preflighted_item(
                        u64::try_from(bytes).map_err(|_| Error::CapacityLimit)?,
                        Some(limits.execution_budget()),
                    )
                },
            ) {
                Ok(value) => value,
                Err(code::ContractObservationAttemptError::Admission(error)) => {
                    return Err(error.into());
                }
                Err(code::ContractObservationAttemptError::Native(
                    ExecutionAttemptError::Deferred(original),
                )) => return Err(ExecutionAttemptError::Deferred(original)),
                Err(code::ContractObservationAttemptError::Native(
                    ExecutionAttemptError::Rejected(_),
                )) => None,
            };
            subject
                .map(|subject| {
                    Ok::<_, QueryAttemptError>(AssetFiControllerBindingV1 {
                        address: canonical(|| address.try_clone_for_admission())?,
                        subject: canonical(|| subject.try_clone_for_admission())?,
                    })
                })
                .transpose()
        })?
    } else {
        None
    };
    let snapshot = measured(&mut graph, maximum, || {
        context::snapshot_from_rows(
            &query.target,
            &query.expected_incarnation,
            &query.expected_uid,
            incarnation,
            source,
            controller,
        )
        .map_err(native_error)
    })?;
    stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
    if canonical(|| norito::canonical_frame_len(&snapshot))? > maximum {
        return Err(Error::CapacityLimit.into());
    }
    let mut rows = ExactOwnedRows::new(1, slots)?;
    rows.push(snapshot)?;
    Ok((rows.finish()?, stats))
}

#[cfg(test)]
mod retained_frame_tests {
    use super::*;
    #[test]
    fn current_context_point_reads_share_one_cumulative_retained_graph() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        let frame = norito::encode_canonical(&vec![7_u8; 128]).unwrap();
        let codec = norito::DecodeLimits::new(4096, 4096, 4096, 4096, 64);
        let (decoded, usage) = norito::core::with_decode_limits_measured(codec, || {
            norito::decode_canonical::<Vec<u8>>(&frame)
        });
        assert_eq!(decoded.unwrap(), vec![7_u8; 128]);
        let bytes = usage.total_allocated_bytes();
        assert!(bytes > 0);
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let first: StatePath = "sc/test_fi_context/first".parse().unwrap();
        let second: StatePath = "sc/test_fi_context/second".parse().unwrap();
        {
            let mut world = state.world.block();
            world
                .smart_contract_state
                .insert(first.clone(), frame.clone());
            world
                .smart_contract_state
                .insert(second.clone(), frame.clone());
            world.commit();
        }
        let limits = super::super::tests::fi_context_test_limits(4096);
        let mut stats = QueryExecutionStats::default();
        let mut exact = RetainedDecodeBudget {
            per_item_graph_bytes: 4096,
            remaining_graph_bytes: u64::try_from(bytes * 2).unwrap(),
        };
        let view = state.view();
        assert_eq!(
            point::<Vec<u8>>(&view, &first, &mut exact, 4096, &mut stats, limits).unwrap(),
            Some(vec![7; 128])
        );
        assert_eq!(
            point::<Vec<u8>>(&view, &second, &mut exact, 4096, &mut stats, limits).unwrap(),
            Some(vec![7; 128])
        );
        let mut short = RetainedDecodeBudget {
            per_item_graph_bytes: 4096,
            remaining_graph_bytes: u64::try_from(bytes * 2 - 1).unwrap(),
        };
        assert!(point::<Vec<u8>>(&view, &first, &mut short, 4096, &mut stats, limits).is_ok());
        assert!(
            point::<Vec<u8>>(&view, &second, &mut short, 4096, &mut stats, limits).is_err(),
            "second valid row cannot reset the first row's allocation owner"
        );
        assert_eq!(
            view.world().smart_contract_state().get(&first),
            Some(&frame)
        );
        assert_eq!(
            view.world().smart_contract_state().get(&second),
            Some(&frame)
        );
    }
}
