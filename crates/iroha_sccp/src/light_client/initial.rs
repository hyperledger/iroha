//! One initialization policy over detached tooling or originally admitted verifier outputs.

use super::{
    prepared::{LcMemory, SccpLcAttemptErrorV1},
    state::writer::DeltaWriter,
    *,
};

/// Scalar initialization result; the writer retains the actual encoded set graph.
#[derive(Clone, Copy, Debug)]
pub(super) struct InitialMetadata {
    pub(super) light_client: SccpLightClientV1,
    pub(super) purge: SccpLcPurgeV1,
}

pub(super) fn bootstrap_into<D: DeltaWriter>(
    profiles: &SccpChainProfilesV1,
    network: SccpNetworkV1,
    params: &SccpLightClientParamsV1,
    decoded: &SccpLcBootstrapDataV1,
    now: u64,
    memory: &LcMemory<'_>,
    output: &mut D,
) -> Result<InitialMetadata, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    ensure_supported(network)?;
    params.validate().map_err(SccpLcError::InvalidParams)?;
    if params.network != network {
        return Err(SccpLcError::NetworkMismatch {
            expected: network,
            found: params.network,
        }
        .into());
    }
    decoded.expect_network(network)?;
    let head = match decoded {
        SccpLcBootstrapDataV1::Ethereum(value) => {
            ethereum::verify_bootstrap_into(&profiles.ethereum, params, value, now, memory, output)?
        }
        SccpLcBootstrapDataV1::Bsc(value) => {
            bsc::verify_bootstrap_into(&profiles.bsc, params, value, now, memory, output)?
        }
        SccpLcBootstrapDataV1::Ton(value) => {
            ton::verify_bootstrap_into(&profiles.ton, params, value, now, memory, output)?
        }
    };
    Ok(InitialMetadata {
        light_client: SccpLightClientV1 {
            params: *params,
            head,
            frozen: None,
            state_hash: state::state_hash(params, &head, None),
        },
        purge: SccpLcPurgeV1::DiscardUnvetted,
    })
}

/// Bootstrap material and the exact committed-state expectation being checked.
#[derive(Clone, Copy)]
pub(super) struct InitialRequest<'a> {
    pub network: SccpNetworkV1,
    pub expected: SccpLcInitExpectationV1,
    pub params: &'a SccpLightClientParamsV1,
    pub decoded: &'a SccpLcBootstrapDataV1,
}

pub(super) fn initialize_into<V: SccpLcStateView + ?Sized, D: DeltaWriter>(
    profiles: &SccpChainProfilesV1,
    view: &V,
    request: InitialRequest<'_>,
    now: u64,
    memory: &LcMemory<'_>,
    output: &mut D,
) -> Result<InitialMetadata, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let InitialRequest {
        network,
        expected,
        params,
        decoded,
    } = request;
    ensure_supported(network)?;
    let aged = match (expected, view.light_client(network)) {
        (SccpLcInitExpectationV1::Absent, None) => None,
        (SccpLcInitExpectationV1::Unusable, Some(installed)) if installed.is_frozen() => None,
        (SccpLcInitExpectationV1::Unusable, Some(installed)) => {
            let stale = match network {
                SccpNetworkV1::EthereumMainnet => {
                    ethereum::is_aged(&profiles.ethereum, &installed, now)
                }
                SccpNetworkV1::BscMainnet => bsc::is_aged(&installed, now),
                SccpNetworkV1::TonMainnet => {
                    ton::weak_subjectivity_deadline_ms_native(
                        &profiles.ton,
                        view,
                        &installed,
                        memory,
                    )? <= now
                }
                SccpNetworkV1::SoraTaira => false,
            };
            if !stale {
                return Err(SccpLcError::UnexpectedLightClientState { network, expected }.into());
            }
            Some(installed)
        }
        _ => return Err(SccpLcError::UnexpectedLightClientState { network, expected }.into()),
    };
    let mut result = bootstrap_into(profiles, network, params, decoded, now, memory, output)?;
    if let Some(installed) = aged {
        result.purge = SccpLcPurgeV1::KeepStored;
        let supersession = match network {
            SccpNetworkV1::EthereumMainnet => {
                ethereum::aged_supersession(&profiles.ethereum, view, &installed)?
            }
            SccpNetworkV1::BscMainnet => bsc::aged_supersession(view, &installed),
            SccpNetworkV1::TonMainnet => ton::aged_supersession_native(view, &installed, memory)?,
            SccpNetworkV1::SoraTaira => None,
        };
        if let Some(row) = supersession {
            output
                .supersede(row.set_id, row.superseded_at_source_ms)
                .map_err(Into::into)?;
        }
    }
    for checkpoint in output.checkpoints() {
        let height = checkpoint.data.source_height;
        if let Some(stored) = view.checkpoint(network, height) {
            let survives = result.purge == SccpLcPurgeV1::KeepStored
                || stored.origin == SccpLcCheckpointOriginV1::Parliament;
            if survives && !state::same_checkpoint_block(&stored.data, &checkpoint.data) {
                return Err(
                    SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::Checkpoint {
                        source_height: height,
                    })
                    .into(),
                );
            }
        }
    }
    if result.purge == SccpLcPurgeV1::KeepStored {
        for index in 0..output.set_count() {
            let set = output
                .set(index)
                .ok_or(SccpLcAttemptErrorV1::Invariant("missing bootstrap output"))?;
            if view
                .consensus_set(network, set.set_id)
                .is_some_and(|old| old.set_bytes != set.set_bytes)
            {
                return Err(
                    SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::ConsensusSet {
                        set_id: set.set_id,
                    })
                    .into(),
                );
            }
        }
    }
    Ok(result)
}
