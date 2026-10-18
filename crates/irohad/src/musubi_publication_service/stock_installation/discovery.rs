//! Cold ordinary account discovery from one actual current native cut.

use super::{Cache, Error as FactoryError};
use iroha_allocation::{AllocationBudget, AllocationCharge};
use iroha_core::{
    state::{State, StateReadOnly},
    sumeragi::finality::{NativeFinalityCursorErrorV1, NativeFinalityCursorV1},
};
use iroha_data_model::{
    NetworkId,
    sorafs::{
        capacity::ProviderId,
        provider_admission::discovery::{
            MAX_PROVIDER_DISCOVERY_ADVERT_BYTES_V1, MAX_PROVIDER_DISCOVERY_BYTES_V1,
            ProviderDiscoveryProofRefV1, ProviderDiscoveryProofV1,
            account_read::VerifiedAccountReadProviderV1,
        },
    },
};
use iroha_storage_client::musubi_archive_fetch::{
    MusubiArchiveDiscoveryErrorV1 as Error, MusubiArchiveProviderDiscoveryV1,
};
use sorafs_car::gateway::GeneratedLocalProviderTransportV1;
use std::{
    alloc::Layout,
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) fn prepare(
    state: Arc<State>,
    cache: Cache,
    originals: [GeneratedLocalProviderTransportV1; 3],
    timeout: Duration,
    selection_charge: AllocationCharge,
) -> Result<Arc<MusubiArchiveProviderDiscoveryV1>, FactoryError> {
    if timeout.is_zero() || timeout > Duration::from_millis(iroha_config::parameters::defaults::musubi_publication::MAX_READBACK_REQUEST_TIMEOUT_MS) { return Err(FactoryError::Unqualified); }
    let budget = state.ivm_execution_budget();
    let network = *state.network_id_ref();
    let chain = state.view().chain_id().to_string();
    // The closed service serializes readback calls. This bounds retained verified admission
    // projections while the callback/client exists; full temporary World proof is funded below.
    let layout =
        Layout::array::<u8>(3 * 16 * 1024 * 1024).map_err(|_| FactoryError::Unavailable)?;
    let result_charge = budget
        .try_reserve(layout)
        .map_err(|_| FactoryError::Unavailable)?
        .try_split(layout)
        .map_err(|_| FactoryError::Unavailable)?;
    let selected = Discovery {
        state,
        cache,
        originals,
        timeout,
        budget,
        network,
        chain,
        cursor: Mutex::new(NativeFinalityCursorV1::new(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )),
        _selection_charge: selection_charge,
        _result_charge: result_charge,
    };
    Ok(Arc::new(move |provider| selected.read(provider)))
}

struct Discovery {
    state: Arc<State>,
    cache: Cache,
    originals: [GeneratedLocalProviderTransportV1; 3],
    timeout: Duration,
    budget: AllocationBudget,
    network: NetworkId,
    chain: String,
    cursor: Mutex<NativeFinalityCursorV1>,
    _selection_charge: AllocationCharge,
    _result_charge: AllocationCharge,
}
impl Discovery {
    fn read(&self, provider: ProviderId) -> Result<VerifiedAccountReadProviderV1, Error> {
        // No clock, source acquisition, callback or network request precedes exact selection.
        let original = self
            .originals
            .iter()
            .find(|original| original.provider_id() == provider)
            .ok_or(Error::Rejected)?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(Error::Deadline)?;
        let started = now()?;
        let view = self.state.view();
        let height = u64::try_from(view.height()).map_err(|_| Error::Unavailable)?;
        if height < 2
            || view.network_id() != &self.network
            || view.chain_id().as_str() != self.chain
        {
            return Err(Error::Unavailable);
        }
        let mut cursor = self.cursor.try_lock().map_err(|_| Error::Unavailable)?;
        let current = cursor
            .advance_current(&view, &self.budget, deadline, NonZeroU16::new(64).unwrap())
            .map_err(|error| match error {
                NativeFinalityCursorErrorV1::Deadline => Error::Deadline,
                _ => Error::Unavailable,
            })?
            .ok_or(Error::Unavailable)?;
        drop(cursor);
        check(deadline)?;
        let tip = current.native_block();
        drop(view);
        let observed = now()?;
        if observed < started {
            return Err(Error::Unavailable);
        }
        check(deadline)?;
        let guard = self.cache.try_read().map_err(|_| Error::Unavailable)?;
        let advert = guard
            .unverified_record_for_native_proof(provider.as_bytes())
            .ok_or(Error::Unavailable)?
            .advert();
        let length = norito::canonical_frame_len(advert).map_err(|_| Error::Rejected)?;
        if length > MAX_PROVIDER_DISCOVERY_ADVERT_BYTES_V1 {
            return Err(Error::Rejected);
        }
        let advert_charge = self
            .budget
            .try_reserve_bytes(length)
            .map_err(|_| Error::Unavailable)?;
        let advert = {
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::to_bytes_bounded(advert, length).map_err(|_| Error::Unavailable)?
        };
        drop(guard);
        check(deadline)?;
        let proof_charge = self
            .budget
            .try_reserve_bytes(MAX_PROVIDER_DISCOVERY_BYTES_V1 + 2 * 128 * 1024 * 1024)
            .map_err(|_| Error::Unavailable)?;
        let result = self
            .state
            .with_native_provider_admission_snapshot_v1(tip, provider, &self.budget, |originals| {
                check(deadline).map_err(|_| "native discovery deadline".to_owned())?;
                // One cumulative decoder allowance covers proof and nested native material
                // verification. An equal prepaid envelope covers their bounded model clones.
                norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(
                        131_072,
                        MAX_PROVIDER_DISCOVERY_BYTES_V1,
                        131_072,
                        128 * 1024 * 1024,
                        64,
                    ),
                    || {
                        let borrowed = ProviderDiscoveryProofRefV1::new(
                            originals.world,
                            (originals.council_head, originals.council_predecessor),
                            (originals.provider_head, originals.provider_predecessor),
                            originals.owner,
                            &advert,
                            originals.stream_token,
                        );
                        let length = norito::canonical_frame_len(&borrowed)
                            .map_err(|_| "native discovery extent".to_owned())?;
                        if length > MAX_PROVIDER_DISCOVERY_BYTES_V1 {
                            return Err("native discovery extent".to_owned());
                        }
                        check(deadline).map_err(|_| "native discovery deadline".to_owned())?;
                        let bytes = {
                            let _flags = norito::core::DecodeFlagsGuard::enter(
                                norito::core::default_encode_flags(),
                            );
                            norito::core::to_bytes_bounded(&borrowed, length)
                                .map_err(|_| "native discovery encoding".to_owned())?
                        };
                        let proof = ProviderDiscoveryProofV1::decode_frame(&bytes)
                            .map_err(|_| "native discovery decoding".to_owned())?;
                        check(deadline).map_err(|_| "native discovery deadline".to_owned())?;
                        let result = proof
                            .verify_account_read(
                                &self.chain,
                                self.network,
                                provider,
                                State::native_world_schema_hash_v1()
                                    .map_err(|_| "native schema unavailable".to_owned())?,
                                current.block(),
                                observed,
                            )
                            .map_err(|_| "native account discovery refused".to_owned())?;
                        // Keep the full temporary envelope until the decoded result is proved to
                        // match the small exact retained original transport graph.
                        original
                            .authenticate_current(&result)
                            .map_err(|_| "native original transport differs".to_owned())?;
                        Ok(result)
                    },
                )
            })
            .map_err(|_| Error::Unavailable)?;
        drop(proof_charge);
        drop(advert);
        drop(advert_charge);
        check(deadline)?;
        let after = now()?;
        if after < observed
            || after >= result.enrollment_expires_at_unix_ms()
            || after / 1000 >= result.discovery().advert().expires_at
            || after / 1000 >= result.discovery().admission().envelope().retention_epoch
        {
            return Err(Error::Unavailable);
        }
        let view = self.state.view();
        if u64::try_from(view.height()).ok() != Some(height)
            || view.latest_block_hash() != Some(tip.block_hash())
            || view.kura().exact_durable_blocks_count().ok() != Some(view.block_hashes().len())
        {
            return Err(Error::Unavailable);
        }
        check(deadline)?;
        Ok(result)
    }
}
fn check(deadline: Instant) -> Result<(), Error> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(Error::Deadline)
    }
}
fn now() -> Result<u64, Error> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_millis();
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(Error::Unavailable)
}
