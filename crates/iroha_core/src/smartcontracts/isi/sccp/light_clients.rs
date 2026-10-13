//! Inbound light clients (`specs/sccp.md` §4.13). Owners: ws33 (Parliament half:
//! [`is_usable`], [`initialize`], [`install_checkpoint`], [`freeze`], [`activate_profile`]) and
//! ws41 (advance half: [`execute_advance`], [`execute_report_equivocation`],
//! [`verify_source_proof`], [`preverify_keeper_advance`], [`prune`]).
//!
//! World state stores authenticated source validator sets with validity ranges and finalized
//! checkpoints. Every advance is permissionless and proof-carrying; the Parliament only
//! initializes, re-initializes, freezes, installs trusted checkpoints and activates compiled
//! profile versions. Chain verification itself lives in `iroha_sccp::light_client`.
//!
//! **Profile versions (§4.13.2).** Every verifier call runs under the compiled profile versions
//! active at the executing height ([`active_profiles_at`]). A release that does not compile an
//! active version (or compiles other content under it) defers the attempt with
//! `VerifierArtifactsUnavailable`, so the node refuses to apply the block instead of verifying
//! under different rules; the same holds for enacting an activation of a version it does not
//! compile.

use super::{
    Error,
    admission::{SccpAdmissionKeysV1, SccpAdmissionRejectV1},
    store,
};
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::sccp::{AdvanceSccpLightClientV1, ReportSccpLightClientEquivocationV1},
    sccp::{
        events::{
            SccpEvent, SccpLightClientAdvancedV1, SccpLightClientFrozenV1,
            SccpLightClientInitializedV1, SccpTrustedCheckpointInstalledV1,
        },
        governance::{
            SccpActivateLightClientProfileActionV1, SccpFreezeLightClientActionV1,
            SccpInitializeLightClientActionV1, SccpInstallTrustedCheckpointActionV1,
        },
        inbound::SccpSourceProofBytesV1,
        light_client::{
            SCCP_LC_GENESIS_PROFILE_VERSION_V1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1,
            SccpLcFreezeReasonV1, SccpLcParliamentFreezeV1, SccpLcProfileActivationV1,
            SccpLightClientV1,
        },
    },
};
use iroha_sccp::light_client::{
    self as lc,
    prepared::{PreparedLcFrameV1, SccpAdmittedProofV1, SccpLcAttemptErrorV1},
    profile::{
        SCCP_LC_PROFILE_NETWORKS_V1, SccpChainProfilesV1, SccpLcActiveProfilesV1,
        SccpLcProfileCatalogV1, SccpLcProfileRefV1, SccpLcProfileUnavailableV1,
    },
    state::admitted::{SccpLcAdmittedDeltaV1, SccpLcDeltaReadV1},
    state::{SccpLcConsensusSetRefV1, SccpLcPurgeV1, SccpLcStateView, state_hash},
};

/// [`SccpLcStateView`] over committed or executing world state.
pub struct WorldLightClientView<'world, W: WorldReadOnly + ?Sized>(pub &'world W);

impl<W: WorldReadOnly + ?Sized> SccpLcStateView for WorldLightClientView<'_, W> {
    fn light_client(&self, network: SccpNetworkV1) -> Option<SccpLightClientV1> {
        store::light_clients::get(self.0, &network).copied()
    }
    fn consensus_set(
        &self,
        network: SccpNetworkV1,
        set_id: u64,
    ) -> Option<SccpLcConsensusSetRefV1<'_>> {
        store::light_client_sets::get(self.0, &(network, set_id)).map(|set| set.as_ref())
    }
    fn checkpoint(&self, network: SccpNetworkV1, source_height: u64) -> Option<SccpLcCheckpointV1> {
        store::light_client_checkpoints::get(self.0, &(network, source_height)).copied()
    }
}

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP light client: {reason}").into())
}

/// Preserve the original local verifier refusal until the enclosing execution aborts.
fn native_attempt_error(
    state: &mut StateTransaction<'_, '_>,
    error: SccpLcAttemptErrorV1,
) -> Error {
    let classified = SccpAdmissionRejectV1::from_attempt(error);
    match classified.deferred {
        Some(original) => {
            let _ = state.defer_execution(original);
            refuse("native verifier resources unavailable; the block is not applied")
        }
        None => refuse(classified.reason),
    }
}

/// Retain authenticated validator bytes under the original execution pool before publication.
pub(crate) fn insert_consensus_set(
    state: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    source: SccpLcConsensusSetRefV1<'_>,
) -> Result<(), Error> {
    let owner =
        super::light_client_set::RetainedSccpLcSet::admit(source, &state.execution_budget())
            .map_err(|error| native_attempt_error(state, error))?;
    store::light_client_sets::insert(state, (network, owner.set_id), owner)?;
    Ok(())
}

/// The first `[zk.sccp]` limit that one verifier call's `work`, the transaction total `in_tx` or
/// the block total `in_block` (both including `work`) exceeds (§4.12.1 step 5).
pub(crate) fn exceeded_verifier_limit(
    limits: &iroha_config::parameters::actual::Sccp,
    work: &lc::SccpVerifierWorkV1,
    in_tx: &lc::SccpVerifierWorkV1,
    in_block: &lc::SccpVerifierWorkV1,
) -> Option<&'static str> {
    if work.proof_bytes > limits.max_proof_bytes_per_proof.get() {
        return Some("max_proof_bytes_per_proof");
    }
    let categories: [(u64, u64, u64, u64, &'static str, &'static str); 7] = [
        (
            in_tx.proofs.into(),
            in_block.proofs.into(),
            limits.max_proofs_per_transaction.get().into(),
            limits.max_proofs_per_block.get().into(),
            "max_proofs_per_transaction",
            "max_proofs_per_block",
        ),
        (
            in_tx.proof_bytes,
            in_block.proof_bytes,
            limits.max_proof_bytes_per_transaction.get(),
            limits.max_proof_bytes_per_block.get(),
            "max_proof_bytes_per_transaction",
            "max_proof_bytes_per_block",
        ),
        (
            in_tx.native_headers.into(),
            in_block.native_headers.into(),
            limits.max_native_headers_per_transaction.get().into(),
            limits.max_native_headers_per_block.get().into(),
            "max_native_headers_per_transaction",
            "max_native_headers_per_block",
        ),
        (
            in_tx.native_header_bytes,
            in_block.native_header_bytes,
            limits.max_native_header_bytes_per_transaction.get(),
            limits.max_native_header_bytes_per_block.get(),
            "max_native_header_bytes_per_transaction",
            "max_native_header_bytes_per_block",
        ),
        (
            in_tx.ethereum_light_client_updates.into(),
            in_block.ethereum_light_client_updates.into(),
            limits
                .max_ethereum_light_client_updates_per_transaction
                .get()
                .into(),
            limits
                .max_ethereum_light_client_updates_per_block
                .get()
                .into(),
            "max_ethereum_light_client_updates_per_transaction",
            "max_ethereum_light_client_updates_per_block",
        ),
        (
            in_tx.bls_vote_attestations.into(),
            in_block.bls_vote_attestations.into(),
            limits
                .max_bls_vote_attestations_per_transaction
                .get()
                .into(),
            limits.max_bls_vote_attestations_per_block.get().into(),
            "max_bls_vote_attestations_per_transaction",
            "max_bls_vote_attestations_per_block",
        ),
        (
            in_tx.ed25519_signature_checks.into(),
            in_block.ed25519_signature_checks.into(),
            limits
                .max_ed25519_signature_checks_per_transaction
                .get()
                .into(),
            limits.max_ed25519_signature_checks_per_block.get().into(),
            "max_ed25519_signature_checks_per_transaction",
            "max_ed25519_signature_checks_per_block",
        ),
    ];
    categories
        .into_iter()
        .find_map(|(tx, block, tx_limit, block_limit, tx_name, block_name)| {
            if tx > tx_limit {
                Some(tx_name)
            } else if block > block_limit {
                Some(block_name)
            } else {
                None
            }
        })
}

/// Reserve one verifier call's estimated work, or refuse an undecodable frame or a call over a
/// `[zk.sccp]` limit before any cryptography runs.
fn reserve_work(
    state_transaction: &mut StateTransaction<'_, '_>,
    work: Result<lc::SccpVerifierWorkV1, lc::SccpLcError>,
) -> Result<(), Error> {
    let work = work.map_err(|error| refuse(format_args!("frame: {error}")))?;
    state_transaction
        .reserve_sccp_verifier_work(&work)
        .map_err(|limit| refuse(format_args!("SCCP verifier work exceeds zk.sccp.{limit}")))
}

/// Return the light-client profile active for every network at Taira height `height`
/// (§4.13.2): for each network, its highest recorded activation whose `activation_height` is at
/// most `height`, and otherwise version 1 of `catalog`.
///
/// Recorded activations carry their own profile hash, so the result depends on `catalog` only
/// through the immutable version 1.
#[must_use]
pub fn active_profiles_at(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    catalog: &SccpLcProfileCatalogV1<'_>,
) -> SccpLcActiveProfilesV1 {
    let mut active = catalog.genesis();
    for network in SCCP_LC_PROFILE_NETWORKS_V1 {
        let recorded =
            store::light_client_profiles::range(world, (network, 0)..=(network, u32::MAX))
                .rev()
                .find(|(_, activation)| activation.activation_height <= height);
        if let Some(((_, version), activation)) = recorded {
            active = active.with(
                network,
                SccpLcProfileRefV1 {
                    version: *version,
                    profile_hash: activation.profile_hash,
                },
            );
        }
    }
    active
}

/// Return the newest recorded profile version of `network` whatever its activation height, or 1
/// when the Parliament never activated one: the bound a new activation must exceed.
#[must_use]
pub fn newest_profile_version(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
) -> u32 {
    store::light_client_profiles::range(world, (network, 0)..=(network, u32::MAX))
        .next_back()
        .map_or(SCCP_LC_GENESIS_PROFILE_VERSION_V1, |((_, version), _)| {
            *version
        })
}

/// Check that this release compiles the light-client profile version active for every network
/// at `height`, with the recorded hash (snapshot restore, §4.13.2).
///
/// # Errors
///
/// Returns the first network whose active version this release cannot verify under.
pub fn ensure_profiles_compiled(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
) -> Result<(), SccpLcProfileUnavailableV1> {
    let catalog = SccpLcProfileCatalogV1::compiled();
    catalog
        .resolve(&active_profiles_at(world, height, &catalog))
        .map(drop)
}

/// Fail closed on an active profile version this release cannot verify under: record the
/// `VerifierArtifactsUnavailable` deferral so the node refuses to apply the block (§4.13.2).
fn defer_unavailable(
    state_transaction: &mut StateTransaction<'_, '_>,
    unavailable: SccpLcProfileUnavailableV1,
) -> Error {
    let _ = state_transaction
        .defer_execution(ivm::error::ExecutionDeferral::VerifierArtifactsUnavailable);
    refuse(format_args!("{unavailable}; the block is not applied"))
}

/// Return the compiled profiles active at the executing block height, resolved in `catalog`.
///
/// # Errors
///
/// Defers the attempt (see [`defer_unavailable`]) when `catalog` lacks an active version.
fn executing_profiles_in(
    state_transaction: &mut StateTransaction<'_, '_>,
    catalog: &SccpLcProfileCatalogV1<'_>,
) -> Result<SccpChainProfilesV1, Error> {
    let height = state_transaction.block_height();
    let active = active_profiles_at(&*state_transaction.world, height, catalog);
    catalog
        .resolve(&active)
        .map_err(|unavailable| defer_unavailable(state_transaction, unavailable))
}

/// Return this release's compiled profiles active at the executing block height.
///
/// # Errors
///
/// Defers the attempt when this release lacks an active version.
pub fn executing_profiles(
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<SccpChainProfilesV1, Error> {
    executing_profiles_in(state_transaction, &SccpLcProfileCatalogV1::compiled())
}

/// Return this release's compiled profiles active at height `height` for admission-time
/// pre-verification, which runs against committed state for the next block. Admission is local,
/// so an unavailable version only rejects the transaction here.
///
/// # Errors
///
/// Rejects when this release lacks an active version.
pub fn admission_profiles(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
) -> Result<SccpChainProfilesV1, SccpAdmissionRejectV1> {
    let catalog = SccpLcProfileCatalogV1::compiled();
    catalog
        .resolve(&active_profiles_at(world, height, &catalog))
        .map_err(|unavailable| SccpAdmissionRejectV1::new(unavailable.to_string()))
}

/// Return whether the light client of `network` is installed, not frozen and within its
/// weak-subjectivity bound at Taira time `now_ms` under `profiles`, so burns on its chain are
/// provable (§4.13.2). A network whose light client this release cannot verify is never usable.
#[must_use]
pub fn is_usable(
    world: &(impl WorldReadOnly + ?Sized),
    profiles: &SccpChainProfilesV1,
    network: SccpNetworkV1,
    now_ms: u64,
) -> bool {
    store::light_clients::get(world, &network).is_some_and(|light_client| !light_client.is_frozen())
        && lc::is_aged_with_profiles(profiles, &WorldLightClientView(world), network, now_ms)
            == Ok(false)
}

/// Apply an enacted `ActivateLightClientProfile` (§4.13.2, §4.14.3): record `version` of
/// `network` as active from the next block, with the profile hash the Parliament voted on.
///
/// # Errors
///
/// Refuses (the enactment ends `ExecutionFailed`) a version that does not exceed the network's
/// newest recorded version, and a version `catalog` compiles with another hash. Defers the
/// attempt, refusing the block, when `catalog` does not compile the version: this release
/// cannot tell an unknown version from a newer one, and must not record what it cannot verify.
fn activate_profile_in(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpActivateLightClientProfileActionV1,
    proposal_id: [u8; 32],
    catalog: &SccpLcProfileCatalogV1<'_>,
) -> Result<(), Error> {
    let network = action.network;
    if !network.is_external() {
        return Err(refuse("light-client profiles belong to external networks"));
    }
    let newest = newest_profile_version(&*state_transaction.world, network);
    if action.version <= newest {
        return Err(refuse(format_args!(
            "{} profile version {} does not exceed the newest activated version {newest}",
            network.profile_key(),
            action.version
        )));
    }
    let profile = SccpLcProfileRefV1 {
        version: action.version,
        profile_hash: action.profile_hash,
    };
    match catalog.check(network, profile) {
        Ok(()) => {}
        Err(mismatch @ SccpLcProfileUnavailableV1::HashMismatch { .. }) => {
            return Err(refuse(format_args!("{mismatch}")));
        }
        Err(unknown @ SccpLcProfileUnavailableV1::NotCompiled { .. }) => {
            return Err(defer_unavailable(state_transaction, unknown));
        }
    }
    let activation_height = state_transaction
        .block_height()
        .checked_add(1)
        .ok_or_else(|| refuse("the activation height overflows"))?;
    store::light_client_profiles::insert(
        state_transaction,
        (network, action.version),
        SccpLcProfileActivationV1 {
            profile_hash: action.profile_hash,
            activation_height,
            proposal_id,
        },
    )?;
    Ok(())
}

/// Apply an enacted `ActivateLightClientProfile` against this release's compiled profiles; see
/// [`activate_profile_in`].
///
/// # Errors
///
/// Refuses a non-monotone version or a hash mismatch; defers on a version this release does not
/// compile.
pub fn activate_profile(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpActivateLightClientProfileActionV1,
    proposal_id: [u8; 32],
) -> Result<(), Error> {
    activate_profile_in(
        state_transaction,
        action,
        proposal_id,
        &SccpLcProfileCatalogV1::compiled(),
    )
}

/// Write `checkpoint` of `network` (replacing a same-height record) and keep the lowest
/// checkpoint of its stride bucket in the permanent stride index (§4.13.1).
///
/// # Errors
///
/// Fails when the stored index breaks its invariant.
pub fn record_checkpoint(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    checkpoint: SccpLcCheckpointV1,
) -> Result<(), Error> {
    let height = checkpoint.data.source_height;
    store::light_client_checkpoints::insert(state_transaction, (network, height), checkpoint)?;
    let stride = store::light_clients::get(&*state_transaction.world, &network)
        .map_or(0, |light_client| light_client.params.checkpoint_stride);
    if let Some(bucket) = height.checked_div(stride) {
        let lowest =
            store::light_client_stride_index::get(&*state_transaction.world, &(network, bucket))
                .copied();
        if lowest.is_none_or(|lowest| height < lowest) {
            store::light_client_stride_index::insert(state_transaction, (network, bucket), height)?;
        }
    }
    Ok(())
}

/// Delete what `purge` names for `network` before a (re-)initialization (§4.13.2).
fn purge(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    purge: SccpLcPurgeV1,
) -> Result<(), Error> {
    if purge == SccpLcPurgeV1::KeepStored {
        return Ok(());
    }
    loop {
        let first = store::light_client_sets::range(
            &*state_transaction.world,
            (network, 0)..=(network, u64::MAX),
        )
        .next()
        .map(|((_, id), _)| *id);
        let Some(set_id) = first else { break };
        if store::light_client_sets::remove(state_transaction, (network, set_id)).is_none() {
            return Err(refuse("original set removal did not complete"));
        }
    }
    let mut cursor = 0;
    loop {
        let first = store::light_client_checkpoints::range(
            &*state_transaction.world,
            (network, cursor)..=(network, u64::MAX),
        )
        .next()
        .map(|((_, id), value)| (*id, value.origin == SccpLcCheckpointOriginV1::Parliament));
        let Some((height, parliament)) = first else {
            break;
        };
        if !parliament
            && store::light_client_checkpoints::remove(state_transaction, (network, height))
                .is_none()
        {
            return Err(refuse("original checkpoint removal did not complete"));
        }
        let Some(next) = height.checked_add(1) else {
            break;
        };
        cursor = next;
    }
    // The stride index is rebuilt below from the surviving Parliament checkpoints.
    loop {
        let first = store::light_client_stride_index::range(
            &*state_transaction.world,
            (network, 0)..=(network, u64::MAX),
        )
        .next()
        .map(|((_, id), _)| *id);
        let Some(bucket) = first else { break };
        if store::light_client_stride_index::remove(state_transaction, (network, bucket)).is_none()
        {
            return Err(refuse("original stride removal did not complete"));
        }
    }
    Ok(())
}

/// Rebuild the stride index of `network` from its stored checkpoints.
fn reindex_strides(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
) -> Result<(), Error> {
    let mut cursor = 0;
    loop {
        let first = store::light_client_checkpoints::range(
            &*state_transaction.world,
            (network, cursor)..=(network, u64::MAX),
        )
        .next()
        .map(|(_, value)| *value);
        let Some(checkpoint) = first else { break };
        record_checkpoint(state_transaction, network, checkpoint)?;
        let Some(next) = checkpoint.data.source_height.checked_add(1) else {
            break;
        };
        cursor = next;
    }
    Ok(())
}

/// Apply an enacted `InitializeLightClient` (§4.14.3).
///
/// The expectation, the freshness of the bootstrap at the enactment block time and conflicts
/// with surviving stored data are checked by `iroha_sccp::light_client`; this applies its
/// result in order (purge, supersessions, light client, sets, checkpoints) and emits
/// `SccpLightClientInitialized`.
///
/// # Errors
///
/// Fails when the expectation does not hold or the bootstrap is invalid or stale.
pub fn initialize(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpInitializeLightClientActionV1,
    proposal_id: [u8; 32],
) -> Result<(), Error> {
    let network = action.network;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let profiles = executing_profiles(state_transaction)?;
    if action.bootstrap.network != network {
        return Err(refuse("bootstrap network mismatch"));
    }
    let budget = state_transaction.execution_budget();
    let maximum = usize::try_from(state_transaction.zk().sccp.max_proof_bytes_per_proof.get())
        .unwrap_or(usize::MAX);
    let prepared =
        lc::prepared::PreparedLcFrameV1::bootstrap(&action.bootstrap.bytes, maximum, &budget)
            .map_err(|error| native_attempt_error(state_transaction, error))?;
    reserve_work(state_transaction, Ok(prepared.work()))?;
    let initial = prepared
        .verify_initialization(
            &profiles,
            &WorldLightClientView(&*state_transaction.world),
            network,
            action.expected,
            &action.params,
            now_ms,
        )
        .map_err(|error| native_attempt_error(state_transaction, error))?;
    purge(state_transaction, network, initial.purge)?;
    for supersession in initial.delta.superseded() {
        let key = (network, supersession.set_id);
        if let Some(mut set) =
            store::light_client_sets::get(&*state_transaction.world, &key).cloned()
        {
            set.superseded_at_source_ms = Some(supersession.superseded_at_source_ms);
            store::light_client_sets::insert(state_transaction, key, set)?;
        }
    }
    let light_client = initial.light_client;
    store::light_clients::insert(state_transaction, network, light_client)?;
    for index in 0..initial.delta.set_count() {
        let set = initial
            .delta
            .set(index)
            .ok_or_else(|| refuse("missing admitted bootstrap set"))?;
        insert_consensus_set(state_transaction, network, set)?;
    }
    if initial.purge == SccpLcPurgeV1::DiscardUnvetted {
        reindex_strides(state_transaction, network)?;
    }
    for checkpoint in initial.delta.checkpoints() {
        record_checkpoint(state_transaction, network, *checkpoint)?;
    }
    state_transaction
        .world
        .emit_events(Some(SccpEvent::LightClientInitialized(
            SccpLightClientInitializedV1 {
                network,
                latest_set_id: light_client.head.latest_set_id,
                latest_finalized: light_client.head.latest_finalized,
                state_hash: light_client.state_hash,
                proposal_id,
            },
        )));
    Ok(())
}

/// Apply an enacted `InstallTrustedCheckpoint` (§4.14.3).
///
/// # Errors
///
/// Fails for TON (its light client reads no checkpoints), when the light client is not
/// installed, the checkpoint is malformed, or it conflicts with a stored checkpoint at the same
/// height.
pub fn install_checkpoint(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpInstallTrustedCheckpointActionV1,
    proposal_id: [u8; 32],
) -> Result<(), Error> {
    let network = action.network;
    let checkpoint = lc::verify_trusted_checkpoint(
        &WorldLightClientView(&*state_transaction.world),
        network,
        &action.checkpoint,
        state_transaction.block_unix_timestamp_ms(),
    )
    .map_err(|error| {
        refuse(format_args!(
            "trusted checkpoint of {}: {error}",
            network.profile_key()
        ))
    })?;
    record_checkpoint(state_transaction, network, checkpoint)?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::TrustedCheckpointInstalled(
            SccpTrustedCheckpointInstalledV1 {
                network,
                source_height: checkpoint.data.source_height,
                block_hash: checkpoint.data.block_hash,
                proposal_id,
            },
        )));
    Ok(())
}

/// Apply an enacted `FreezeLightClient` (§4.14.3).
///
/// A light client that is already frozen keeps its original reason, so equivocation evidence
/// is never overwritten.
///
/// # Errors
///
/// Fails when the light client is not installed.
pub fn freeze(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpFreezeLightClientActionV1,
    proposal_id: [u8; 32],
) -> Result<(), Error> {
    let network = action.network;
    let mut light_client = store::light_clients::get(&*state_transaction.world, &network)
        .copied()
        .ok_or_else(|| refuse(format_args!("{} is not installed", network.profile_key())))?;
    if light_client.is_frozen() {
        return Ok(());
    }
    let reason = SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 { proposal_id });
    light_client.frozen = Some(reason);
    light_client.state_hash = state_hash(&light_client.params, &light_client.head, Some(&reason));
    store::light_clients::insert(state_transaction, network, light_client)?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::LightClientFrozen(
            SccpLightClientFrozenV1 { network, reason },
        )));
    Ok(())
}

/// Apply a verified light-client `delta` of `network` (§4.13.2): new sets, supersessions,
/// checkpoints (idempotent, stride-indexed) and the head. Return whether the head moved.
///
/// # Errors
///
/// Fails when a stored map breaks its invariant.
fn apply_delta(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    current: &SccpLightClientV1,
    delta: &SccpLcAdmittedDeltaV1,
) -> Result<bool, Error> {
    for index in 0..delta.set_count() {
        let set = delta
            .set(index)
            .ok_or_else(|| refuse("admitted set row missing"))?;
        insert_consensus_set(state_transaction, network, set)?;
    }
    for supersession in delta.superseded() {
        let key = (network, supersession.set_id);
        if let Some(mut set) =
            store::light_client_sets::get(&*state_transaction.world, &key).cloned()
        {
            set.superseded_at_source_ms = Some(supersession.superseded_at_source_ms);
            store::light_client_sets::insert(state_transaction, key, set)?;
        }
    }
    for checkpoint in delta.checkpoints() {
        record_checkpoint(state_transaction, network, *checkpoint)?;
    }
    if let Some(head) = delta.head() {
        let mut next = *current;
        next.head = head;
        next.state_hash = state_hash(&next.params, &head, next.frozen.as_ref());
        store::light_clients::insert(state_transaction, network, next)?;
        state_transaction
            .world
            .emit_events(Some(SccpEvent::LightClientAdvanced(
                SccpLightClientAdvancedV1 {
                    network,
                    latest_set_id: next.head.latest_set_id,
                    latest_finalized: next.head.latest_finalized,
                    state_hash: next.state_hash,
                },
            )));
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Execute `AdvanceSccpLightClientV1` (§4.13.2).
///
/// The optional `expected_state_hash` is a compare-and-swap guard. Re-proving stored data is a
/// successful no-op, so concurrent keepers and wallets do not fail.
///
/// # Errors
///
/// Fails when the guard does not match, or the advance does not verify (a conflict with stored
/// data points to `ReportSccpLightClientEquivocationV1`).
pub fn execute_advance(
    instruction: AdvanceSccpLightClientV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let network = instruction.network;
    let current = store::light_clients::get(&*state_transaction.world, &network)
        .copied()
        .ok_or_else(|| refuse(format_args!("{} is not installed", network.profile_key())))?;
    if instruction
        .expected_state_hash
        .is_some_and(|expected| expected != current.state_hash)
    {
        return Err(refuse("the light client moved since the advance was built"));
    }
    let maximum = usize::try_from(state_transaction.zk().sccp.max_proof_bytes_per_proof.get())
        .unwrap_or(usize::MAX);
    let prepared = PreparedLcFrameV1::advance(
        instruction.advance.as_bytes(),
        maximum,
        &state_transaction.execution_budget(),
    )
    .map_err(|error| native_attempt_error(state_transaction, error))?;
    reserve_work(state_transaction, Ok(prepared.work()))?;
    let profiles = executing_profiles(state_transaction)?;
    let delta = prepared
        .verify_advance(
            &profiles,
            &WorldLightClientView(&*state_transaction.world),
            network,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| native_attempt_error(state_transaction, error))?;
    apply_delta(state_transaction, network, &current, &delta).map(|_| ())
}

/// Execute `ReportSccpLightClientEquivocationV1`: two quorum-valid conflicting records freeze
/// the light client (§4.13.2).
///
/// # Errors
///
/// Fails when the evidence does not prove an equivocation.
pub fn execute_report_equivocation(
    instruction: ReportSccpLightClientEquivocationV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let network = instruction.network;
    let mut light_client = store::light_clients::get(&*state_transaction.world, &network)
        .copied()
        .ok_or_else(|| refuse(format_args!("{} is not installed", network.profile_key())))?;
    if light_client.is_frozen() {
        return Err(refuse("the light client is already frozen"));
    }
    let budget = state_transaction.execution_budget();
    let maximum = usize::try_from(state_transaction.zk.sccp.max_proof_bytes_per_proof.get())
        .unwrap_or(usize::MAX);
    let prepared = lc::prepared::PreparedLcEvidencePairV1::new(
        instruction.a.as_bytes(),
        instruction.b.as_bytes(),
        maximum,
        &budget,
    )
    .map_err(|error| native_attempt_error(state_transaction, error))?;
    let work = prepared
        .work()
        .map_err(|error| native_attempt_error(state_transaction, error))?;
    reserve_work(state_transaction, Ok(work))?;
    let profiles = executing_profiles(state_transaction)?;
    let reason = prepared
        .verify(
            &profiles,
            &WorldLightClientView(&*state_transaction.world),
            network,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| native_attempt_error(state_transaction, error))?;
    light_client.frozen = Some(reason);
    light_client.state_hash = state_hash(&light_client.params, &light_client.head, Some(&reason));
    store::light_clients::insert(state_transaction, network, light_client)?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::LightClientFrozen(
            SccpLightClientFrozenV1 { network, reason },
        )));
    Ok(())
}

/// Verify an inbound or void `proof` against `network`'s light client at the executing block
/// time, record the checkpoints it proved, and return the normalized source event (§4.12.1
/// step 4).
///
/// The proof's verifier work is reserved under the `[zk.sccp]` limits first.
///
/// # Errors
///
/// Fails when the light client is unusable or the proof does not verify.
pub fn verify_source_proof(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    proof: &SccpSourceProofBytesV1,
) -> Result<SccpAdmittedProofV1, Error> {
    let maximum = usize::try_from(state_transaction.zk().sccp.max_proof_bytes_per_proof.get())
        .unwrap_or(usize::MAX);
    let prepared = PreparedLcFrameV1::proof(
        proof.as_bytes(),
        maximum,
        &state_transaction.execution_budget(),
    )
    .map_err(|error| native_attempt_error(state_transaction, error))?;
    reserve_work(state_transaction, Ok(prepared.work()))?;
    let profiles = executing_profiles(state_transaction)?;
    let verified = prepared
        .verify_proof(
            &profiles,
            &WorldLightClientView(&*state_transaction.world),
            network,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| native_attempt_error(state_transaction, error))?;
    for checkpoint in verified.checkpoints.checkpoints() {
        record_checkpoint(state_transaction, network, *checkpoint)?;
    }
    Ok(verified)
}

/// Return whether `instruction` is an eligible keeper advance (§4.13.4, §4.19): the advance
/// frame decodes for `instruction.network` and is not a `Backfill`. A `Backfill` and an
/// undecodable frame pay the ordinary fee.
///
/// The rule is the same for every authority, registered or not, so it reads neither the
/// authority nor state: [`super::fees::exempt_class`] adds only that SCCP exists, and
/// [`super::admission::allows_unregistered_authority`] admits an absent authority for exactly
/// the advances this function accepts. Whether the advance verifies and moves the head is
/// admission pre-verification ([`preverify_keeper_advance`]), not eligibility.
#[must_use]
pub fn keeper_advance_eligible(instruction: &AdvanceSccpLightClientV1) -> bool {
    lc::proof::keeper_advance_network(instruction.advance.as_bytes()) == Some(instruction.network)
}

/// Pre-verify an eligible keeper advance ([`keeper_advance_eligible`]) and return its
/// admission keys (one pending exempt advance per authority and network, §4.13.4).
///
/// An eligible advance must verify and move the head against committed state, verified under
/// the light-client profiles active at `next_block_height`.
///
/// # Errors
///
/// Rejects an advance of an uninstalled light client or with a stale expected state hash, an
/// advance that does not verify, an advance that would not move the head, and any advance
/// while this release lacks an active profile version.
pub fn preverify_keeper_advance(
    world: &(impl WorldReadOnly + ?Sized),
    view: &(impl super::admission::SccpAdmissionView + ?Sized),
    next_block_height: u64,
    instruction: &AdvanceSccpLightClientV1,
    authority: &AccountId,
) -> Result<SccpAdmissionKeysV1, SccpAdmissionRejectV1> {
    let network = instruction.network;
    let current = store::light_clients::get(world, &network)
        .ok_or_else(|| SccpAdmissionRejectV1::new("the light client is not installed"))?;
    if instruction
        .expected_state_hash
        .is_some_and(|expected| expected != current.state_hash)
    {
        return Err(SccpAdmissionRejectV1::new("stale expected state hash"));
    }
    let profiles = admission_profiles(world, next_block_height)?;
    let limits = view.sccp_verifier_limits();
    let budget = view.sccp_execution_budget();
    let prepared = lc::prepared::PreparedLcFrameV1::advance(
        instruction.advance.as_bytes(),
        usize::try_from(limits.max_proof_bytes_per_proof.get()).unwrap_or(usize::MAX),
        &budget,
    )
    .map_err(SccpAdmissionRejectV1::from_attempt)?;
    let work = prepared.work();
    if let Some(limit) = exceeded_verifier_limit(limits, &work, &work, &work) {
        return Err(SccpAdmissionRejectV1::new(format!(
            "advance exceeds zk.sccp.{limit}"
        )));
    }
    let delta = prepared
        .verify_advance(
            &profiles,
            &WorldLightClientView(world),
            network,
            view.committed_time_ms(),
        )
        .map_err(SccpAdmissionRejectV1::from_attempt)?;
    if iroha_sccp::light_client::state::admitted::SccpLcDeltaReadV1::head(&delta).is_none() {
        return Err(SccpAdmissionRejectV1::new(
            "the advance does not move the head",
        ));
    }
    Ok(keeper_advance_keys(authority, network))
}

/// Return the admission keys of an exempt keeper advance of `network` from `authority`: at
/// most one is pending per authority and network, whether or not the authority is registered
/// (§4.13.4, §4.19).
fn keeper_advance_keys(authority: &AccountId, network: SccpNetworkV1) -> SccpAdmissionKeysV1 {
    SccpAdmissionKeysV1::new(super::admission::SccpExemptClassV1::KeeperAdvance { network })
        .with_exclusive(&(norito::core::PayloadRef(authority), network))
}

/// Prune expired light-client sets and checkpoints, deleting at most `budget` records, and
/// return the number deleted (§4.13.1).
///
/// Sets go `set_retention_ms` after supersession; checkpoints go `checkpoint_prune_after_ms`
/// after recording unless Parliament-installed or the lowest of their stride bucket.
pub fn prune(state_transaction: &mut StateTransaction<'_, '_>, budget: usize) -> usize {
    use iroha_sccp::light_client::state::checkpoint_prune_due;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let mut deleted = 0;
    for network in SCCP_LC_PROFILE_NETWORKS_V1 {
        let Some(params) = store::light_clients::get(&*state_transaction.world, &network)
            .map(|client| client.params)
        else {
            continue;
        };
        let mut cursor = 0;
        while deleted < budget {
            let next = store::light_client_sets::range(
                &*state_transaction.world,
                (network, cursor)..=(network, u64::MAX),
            )
            .next()
            .map(|((_, id), set)| {
                (
                    *id,
                    set.superseded_at_source_ms
                        .is_some_and(|at| at.saturating_add(params.set_retention_ms) <= now_ms),
                )
            });
            let Some((id, due)) = next else { break };
            if due {
                if store::light_client_sets::remove(state_transaction, (network, id)).is_none() {
                    return deleted;
                }
                deleted += 1;
            }
            let Some(next) = id.checked_add(1) else { break };
            cursor = next;
        }
        let mut cursor = 0;
        while deleted < budget {
            let next = store::light_client_checkpoints::range(
                &*state_transaction.world,
                (network, cursor)..=(network, u64::MAX),
            )
            .next()
            .map(|((_, height), checkpoint)| (*height, *checkpoint));
            let Some((height, checkpoint)) = next else {
                break;
            };
            let lowest = height
                .checked_div(params.checkpoint_stride)
                .and_then(|bucket| {
                    store::light_client_stride_index::get(
                        &*state_transaction.world,
                        &(network, bucket),
                    )
                    .copied()
                });
            if checkpoint_prune_due(network, &checkpoint, &params, lowest, now_ms) {
                if store::light_client_checkpoints::remove(state_transaction, (network, height))
                    .is_none()
                {
                    return deleted;
                }
                deleted += 1;
            }
            let Some(next) = height.checked_add(1) else {
                break;
            };
            cursor = next;
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SampleInstructions, authority, blank_state, header,
    };

    #[test]
    fn ordinary_advance_original_pool_refusal_is_a_sticky_execution_deferral() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        store::light_clients::insert(&mut stx, SccpNetworkV1::EthereumMainnet, installed(1))
            .unwrap();
        let budget = stx.execution_budget();
        let limit = budget.limit_bytes();
        let before = budget.reserved_bytes();
        budget.set_limit_bytes(before);
        let result = execute_advance(advance_frame(false), &authority(1), &mut stx);
        budget.set_limit_bytes(limit);
        assert!(result.is_err());
        assert!(
            stx.execution_deferral().is_some(),
            "physical decode refusal must not become protocol rejection"
        );
        assert_eq!(
            budget.reserved_bytes(),
            before,
            "failed preparation retains no partial graph"
        );
        assert_eq!(
            store::light_clients::get(&*stx.world, &SccpNetworkV1::EthereumMainnet),
            Some(&installed(1))
        );
    }

    #[test]
    fn native_delta_retains_set_bytes_and_rolls_back_scalar_supersession() {
        use iroha_sccp::light_client::state::admitted::{
            SccpLcDeltaBuilderV1, SccpLcDeltaCapacityV1,
        };
        let state = blank_state();
        let mut block = state.block(header(2));
        let budget = state.ivm_execution_budget();
        let network = SccpNetworkV1::EthereumMainnet;
        let mut output = SccpLcDeltaBuilderV1::new(
            SccpLcDeltaCapacityV1 {
                new_sets: 1,
                superseded_sets: 1,
                checkpoints: 0,
                set_bytes: 4096,
            },
            &budget,
        )
        .unwrap();
        output.encode_set(7, 42, None, &[9_u64; 16]).unwrap();
        let delta = output.finish(None);
        let original_bytes = delta.set(0).unwrap().set_bytes;
        let retained;
        {
            let mut stx = block.transaction();
            assert!(!apply_delta(&mut stx, network, &installed(1), &delta).unwrap());
            retained = store::light_client_sets::get(&*stx.world, &(network, 7))
                .unwrap()
                .clone();
            assert_eq!(retained.bytes(), original_bytes);
            let mut replacement = retained.clone();
            replacement.superseded_at_source_ms = Some(50);
            store::light_client_sets::insert(&mut stx, (network, 7), replacement).unwrap();
            assert_eq!(retained.superseded_at_source_ms, None);
        }
        assert!(store::light_client_sets::get(&block.world, &(network, 7)).is_none());
        assert_eq!(
            retained.bytes(),
            original_bytes,
            "reader keeps original bytes after transaction rollback"
        );
        drop(delta);
        assert!(
            !retained.bytes().is_empty(),
            "stored owner is independent of ephemeral verifier delta"
        );
    }

    #[test]
    fn advances_and_reports_need_an_installed_light_client() {
        let state = blank_state();
        let view = state.world_view();
        assert!(!is_usable(
            &view,
            SccpChainProfilesV1::genesis(),
            SccpNetworkV1::EthereumMainnet,
            0
        ));
        let reject = preverify_keeper_advance(
            &view,
            &state.view(),
            1,
            &SampleInstructions::advance(),
            &authority(1),
        )
        .expect_err("not installed");
        assert!(reject.reason.contains("not installed"), "{reject}");
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        assert_eq!(prune(&mut stx, 1_024), 0);
        let proof = SccpSourceProofBytesV1::new(vec![1, 2, 3]).expect("bounded proof");
        verify_source_proof(&mut stx, SccpNetworkV1::EthereumMainnet, &proof)
            .expect_err("not installed");
        let error = execute_advance(SampleInstructions::advance(), &authority(1), &mut stx)
            .expect_err("not installed");
        assert!(error.to_string().contains("not installed"), "{error}");
        execute_report_equivocation(SampleInstructions::equivocation(), &authority(1), &mut stx)
            .expect_err("not installed");
    }

    /// Return a decodable advance frame of `network`: an empty Ethereum update list, or an
    /// empty `Backfill` segment.
    pub(crate) fn advance_frame(backfill: bool) -> AdvanceSccpLightClientV1 {
        use iroha_sccp::light_client::{
            ethereum::{EthereumHeaderSegmentV1, EthereumLcAdvanceV1},
            proof::{SccpLcAdvanceV1, SccpLcSegmentV1},
        };
        let advance = if backfill {
            SccpLcAdvanceV1::Backfill {
                segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                    headers: Vec::new(),
                }),
            }
        } else {
            SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
                updates: Vec::new(),
            })
        };
        AdvanceSccpLightClientV1 {
            network: SccpNetworkV1::EthereumMainnet,
            expected_state_hash: None,
            advance: advance.to_bytes().expect("bounded advance"),
        }
    }

    #[test]
    fn keeper_advances_are_eligible_by_their_frame_alone() {
        let advance = advance_frame(false);
        assert!(
            keeper_advance_eligible(&advance),
            "a decodable advance of its network needs no registered key"
        );
        assert!(
            !keeper_advance_eligible(&advance_frame(true)),
            "a Backfill pays the ordinary fee"
        );
        assert!(
            !keeper_advance_eligible(&SampleInstructions::advance()),
            "an undecodable frame pays the ordinary fee"
        );
        let mut other_network = advance;
        other_network.network = SccpNetworkV1::BscMainnet;
        assert!(
            !keeper_advance_eligible(&other_network),
            "a frame of another network pays the ordinary fee"
        );
    }

    #[test]
    fn eligible_keeper_advances_are_preverified_whatever_their_authority() {
        // An unregistered authority's eligible advance is pre-verified like a registered one's:
        // a stale guard, and an advance that proves nothing, are rejected at admission.
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        store::light_clients::insert(&mut stx, network, installed(100)).expect("lc");
        let advance = advance_frame(false);
        assert!(keeper_advance_eligible(&advance));
        for unregistered in [authority(7), authority(8)] {
            let mut stale_advance = advance.clone();
            stale_advance.expected_state_hash = Some([0xee; 32]);
            let reject =
                preverify_keeper_advance(&*stx.world, &stx, 3, &stale_advance, &unregistered)
                    .expect_err("stale guard");
            assert!(reject.reason.contains("stale"), "{reject}");
            preverify_keeper_advance(&*stx.world, &stx, 3, &advance, &unregistered)
                .expect_err("an advance that proves nothing is rejected at admission");
        }
    }

    #[test]
    fn one_exempt_advance_is_pending_per_authority_and_network() {
        use crate::smartcontracts::isi::sccp::admission::{
            SccpExemptClassV1, SccpPendingClaimErrorV1, SccpPendingIndexV1,
        };
        use iroha_crypto::{Hash, HashOf};
        let entry = |seed: u8| HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32]));
        let (eth, bsc) = (SccpNetworkV1::EthereumMainnet, SccpNetworkV1::BscMainnet);
        let keys = keeper_advance_keys(&authority(1), eth);
        let owned = SccpAdmissionKeysV1::new(SccpExemptClassV1::KeeperAdvance { network: eth })
            .with_exclusive(&(authority(1), eth));
        assert_eq!(
            keys.exclusive, owned.exclusive,
            "borrowing the authority preserves the canonical admission key"
        );
        assert_eq!(
            keys.class,
            SccpExemptClassV1::KeeperAdvance { network: eth }
        );
        assert!(keys.content.is_empty());
        let mut index = SccpPendingIndexV1::default();
        index.claim(entry(1), keys).expect("first advance");
        assert_eq!(
            index.claim(entry(2), keeper_advance_keys(&authority(1), eth)),
            Err(SccpPendingClaimErrorV1::ExclusiveHeld { holder: entry(1) })
        );
        index
            .claim(entry(3), keeper_advance_keys(&authority(2), eth))
            .expect("another authority");
        index
            .claim(entry(4), keeper_advance_keys(&authority(1), bsc))
            .expect("another network");
        index.release(&entry(1));
        index
            .claim(entry(2), keeper_advance_keys(&authority(1), eth))
            .expect("the limit is free once the pending advance leaves the queue");
    }

    #[test]
    fn verifier_work_is_reserved_per_transaction_and_block() {
        use lc::SccpVerifierWorkV1 as Work;
        let state = blank_state();
        let mut block = state.block(header(2));
        // The BSC vote attestations one transaction may carry: four full 16-step advances.
        let full_transaction = Work {
            proof_bytes: 1_000,
            native_headers: 2_048,
            bls_vote_attestations: 64,
            ..Work::default()
        };
        let one_attestation = Work {
            bls_vote_attestations: 1,
            ..Work::default()
        };
        {
            let mut stx = block.transaction();
            stx.reserve_sccp_verifier_work(&full_transaction)
                .expect("the per-transaction limit fits one transaction");
            assert_eq!(
                stx.reserve_sccp_verifier_work(&one_attestation),
                Err("max_bls_vote_attestations_per_transaction")
            );
            stx.apply();
        }
        {
            // A dropped transaction releases its reservation.
            let mut stx = block.transaction();
            stx.reserve_sccp_verifier_work(&full_transaction)
                .expect("fits");
        }
        for _ in 0..3 {
            let mut stx = block.transaction();
            stx.reserve_sccp_verifier_work(&full_transaction)
                .expect("four full transactions fit one block");
            stx.apply();
        }
        let mut stx = block.transaction();
        assert_eq!(
            stx.reserve_sccp_verifier_work(&one_attestation),
            Err("max_bls_vote_attestations_per_block")
        );
        let oversized = Work {
            proof_bytes: stx.zk.sccp.max_proof_bytes_per_proof.get() + 1,
            ..Work::default()
        };
        assert_eq!(
            stx.reserve_sccp_verifier_work(&oversized),
            Err("max_proof_bytes_per_proof")
        );
        let error = execute_advance(SampleInstructions::advance(), &authority(1), &mut stx)
            .expect_err("not installed");
        assert!(error.to_string().contains("not installed"), "{error}");
    }

    #[test]
    fn verifier_limits_name_the_first_exceeded_category() {
        use lc::SccpVerifierWorkV1 as Work;
        let limits = iroha_config::parameters::actual::Sccp::default();
        let within = Work {
            bls_vote_attestations: 16,
            ..Work::default()
        };
        assert_eq!(
            exceeded_verifier_limit(&limits, &within, &within, &within),
            None
        );
        let tx = Work {
            bls_vote_attestations: limits.max_bls_vote_attestations_per_transaction.get() + 1,
            ..Work::default()
        };
        assert_eq!(
            exceeded_verifier_limit(&limits, &within, &tx, &tx),
            Some("max_bls_vote_attestations_per_transaction")
        );
        let block = Work {
            ethereum_light_client_updates: limits.max_ethereum_light_client_updates_per_block.get()
                + 1,
            ..Work::default()
        };
        assert_eq!(
            exceeded_verifier_limit(&limits, &within, &within, &block),
            Some("max_ethereum_light_client_updates_per_block")
        );
    }

    #[test]
    fn a_stale_state_hash_guard_refuses_the_advance() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let mut advance = SampleInstructions::advance();
        store::light_clients::insert(&mut stx, advance.network, installed(100)).expect("lc");
        advance.expected_state_hash = Some([9; 32]);
        let error = execute_advance(advance, &authority(1), &mut stx).expect_err("stale");
        assert!(error.to_string().contains("moved"), "{error}");
    }

    #[test]
    fn expired_checkpoints_are_pruned_except_permanent_ones() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        let mut light_client = installed(100);
        light_client.params.checkpoint_prune_after_ms = 1;
        store::light_clients::insert(&mut stx, network, light_client).expect("lc");
        for (height, origin) in [
            (120, SccpLcCheckpointOriginV1::Advance),
            (150, SccpLcCheckpointOriginV1::Advance),
            (160, SccpLcCheckpointOriginV1::Parliament),
        ] {
            record_checkpoint(&mut stx, network, checkpoint(height, origin)).expect("cp");
        }
        // Block 2 runs at 8 000 ms; checkpoints were recorded at 0.
        assert_eq!(
            prune(&mut stx, 1_024),
            1,
            "only the non-lowest advance checkpoint"
        );
        assert!(store::light_client_checkpoints::contains(
            &*stx.world,
            &(network, 120)
        ));
        assert!(!store::light_client_checkpoints::contains(
            &*stx.world,
            &(network, 150)
        ));
        assert!(store::light_client_checkpoints::contains(
            &*stx.world,
            &(network, 160)
        ));
    }

    fn installed(stride: u64) -> SccpLightClientV1 {
        let mut params =
            iroha_data_model::sccp::light_client::SccpLightClientParamsV1::defaults_for(
                SccpNetworkV1::EthereumMainnet,
            )
            .expect("ethereum defaults");
        params.checkpoint_stride = stride;
        let head = iroha_data_model::sccp::light_client::SccpLcHeadV1 {
            latest_set_id: 1,
            latest_finalized: iroha_data_model::sccp::light_client::SccpLcPointV1 {
                source_height: 100,
                block_hash: [1; 32],
                source_time_ms: 1_000,
            },
            last_progress_taira_ms: 0,
        };
        SccpLightClientV1 {
            params,
            head,
            frozen: None,
            state_hash: state_hash(&params, &head, None),
        }
    }

    fn checkpoint(height: u64, origin: SccpLcCheckpointOriginV1) -> SccpLcCheckpointV1 {
        SccpLcCheckpointV1 {
            data: iroha_data_model::sccp::light_client::SccpLcCheckpointDataV1 {
                source_height: height,
                block_hash: [2; 32],
                state_root: None,
                receipts_or_tx_root: [3; 32],
                source_time_ms: height,
            },
            recorded_at_taira_ms: 0,
            origin,
        }
    }

    #[test]
    fn purge_and_reindex_preserve_parliament_and_other_chains_at_extreme_heights() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        let other = SccpNetworkV1::BscMainnet;
        for chain in [network, other] {
            let mut client = installed(8);
            client.params.network = chain;
            store::light_clients::insert(&mut stx, chain, client).unwrap();
            for id in [0, u64::MAX] {
                insert_consensus_set(
                    &mut stx,
                    chain,
                    lc::state::SccpLcConsensusSetRefV1 {
                        set_id: id,
                        valid_from_source_height: id,
                        superseded_at_source_ms: None,
                        set_bytes: &[1, 2, 3],
                    },
                )
                .unwrap();
            }
            for (height, origin) in [
                (0, SccpLcCheckpointOriginV1::Parliament),
                (7, SccpLcCheckpointOriginV1::Advance),
                (8, SccpLcCheckpointOriginV1::Backfill),
                (u64::MAX, SccpLcCheckpointOriginV1::Parliament),
            ] {
                record_checkpoint(&mut stx, chain, checkpoint(height, origin)).unwrap();
            }
        }
        purge(&mut stx, network, SccpLcPurgeV1::KeepStored).unwrap();
        assert!(store::light_client_sets::contains(
            &*stx.world,
            &(network, u64::MAX)
        ));
        assert!(store::light_client_checkpoints::contains(
            &*stx.world,
            &(network, 7)
        ));
        purge(&mut stx, network, SccpLcPurgeV1::DiscardUnvetted).unwrap();
        reindex_strides(&mut stx, network).unwrap();
        for id in [0, u64::MAX] {
            assert!(!store::light_client_sets::contains(
                &*stx.world,
                &(network, id)
            ));
            assert!(store::light_client_sets::contains(
                &*stx.world,
                &(other, id)
            ));
            assert!(store::light_client_checkpoints::contains(
                &*stx.world,
                &(network, id)
            ));
            assert_eq!(
                store::light_client_stride_index::get(&*stx.world, &(network, id / 8)),
                Some(&id)
            );
        }
        for height in [7, 8] {
            assert!(!store::light_client_checkpoints::contains(
                &*stx.world,
                &(network, height)
            ));
            assert!(store::light_client_checkpoints::contains(
                &*stx.world,
                &(other, height)
            ));
        }
        assert!(!store::light_client_stride_index::contains(
            &*stx.world,
            &(network, 1)
        ));
        assert_eq!(
            store::light_client_stride_index::get(&*stx.world, &(other, 1)),
            Some(&8)
        );
    }

    #[test]
    fn checkpoints_keep_the_lowest_height_per_stride_bucket() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        store::light_clients::insert(&mut stx, network, installed(100)).expect("installed");
        for height in [150, 120, 180, 250] {
            record_checkpoint(
                &mut stx,
                network,
                checkpoint(height, SccpLcCheckpointOriginV1::Advance),
            )
            .expect("checkpoint");
        }
        assert_eq!(
            store::light_client_stride_index::get(&*stx.world, &(network, 1)),
            Some(&120)
        );
        assert_eq!(
            store::light_client_stride_index::get(&*stx.world, &(network, 2)),
            Some(&250)
        );
        assert_eq!(store::light_client_checkpoints::len(&*stx.world), 4);
    }

    use iroha_sccp::light_client::profile::{
        BSC_MAINNET_VERSIONS, ETHEREUM_MAINNET, ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH,
        EthereumChainProfileV1, GENESIS_PROFILES, TON_MAINNET_VERSIONS,
    };

    /// Ethereum versions of a later release: version 1 plus versions 2 and 3, each extending
    /// `supported_until`.
    const LATER_ETHEREUM: [EthereumChainProfileV1; 3] = [
        ETHEREUM_MAINNET,
        ETHEREUM_MAINNET.with_supported_until_epoch(ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH + 1),
        ETHEREUM_MAINNET.with_supported_until_epoch(ETHEREUM_MAINNET_SUPPORTED_UNTIL_EPOCH + 2),
    ];

    /// A release that compiles the first `count` of [`LATER_ETHEREUM`].
    fn release_with(count: usize) -> SccpLcProfileCatalogV1<'static> {
        SccpLcProfileCatalogV1 {
            ethereum: &LATER_ETHEREUM[..count],
            bsc: BSC_MAINNET_VERSIONS,
            ton: TON_MAINNET_VERSIONS,
        }
    }

    fn activation(version: u32) -> SccpActivateLightClientProfileActionV1 {
        SccpActivateLightClientProfileActionV1 {
            network: SccpNetworkV1::EthereumMainnet,
            version,
            profile_hash: LATER_ETHEREUM[usize::try_from(version - 1).expect("small")]
                .profile_hash(),
        }
    }

    fn deferred(stx: &StateTransaction<'_, '_>) -> bool {
        stx.execution_deferral().is_some_and(|deferral| {
            deferral.reason() == ivm::error::ExecutionDeferral::VerifierArtifactsUnavailable
        })
    }

    #[test]
    fn activation_is_monotone_checks_the_compiled_hash_and_takes_effect_next_block() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let network = SccpNetworkV1::EthereumMainnet;
        {
            let mut stx = block.transaction();
            let later = release_with(3);
            assert_eq!(newest_profile_version(&*stx.world, network), 1);
            activate_profile_in(&mut stx, &activation(2), [4; 32], &later).expect("version 2");
            assert_eq!(
                store::light_client_profiles::get(&*stx.world, &(network, 2)),
                Some(&SccpLcProfileActivationV1 {
                    profile_hash: LATER_ETHEREUM[1].profile_hash(),
                    activation_height: 6,
                    proposal_id: [4; 32],
                })
            );
            assert_eq!(newest_profile_version(&*stx.world, network), 2);
            // The enacting block still runs version 1; version 2 applies from the next block.
            assert_eq!(
                active_profiles_at(&*stx.world, 5, &later),
                later.genesis(),
                "the enacting block keeps the previous version"
            );
            assert_eq!(
                active_profiles_at(&*stx.world, 6, &later)
                    .get(network)
                    .map(|profile| profile.version),
                Some(2)
            );
            for stale in [1, 2] {
                let error = activate_profile_in(&mut stx, &activation(stale), [5; 32], &later)
                    .expect_err("not above the newest version");
                assert!(error.to_string().contains("does not exceed"), "{error}");
            }
            let mut forged = activation(3);
            forged.profile_hash = [9; 32];
            let error =
                activate_profile_in(&mut stx, &forged, [5; 32], &later).expect_err("another hash");
            assert!(
                error.to_string().contains("another profile hash"),
                "{error}"
            );
            assert!(
                !deferred(&stx),
                "a hash mismatch is a deterministic refusal"
            );
            let mut taira = activation(3);
            taira.network = SccpNetworkV1::SoraTaira;
            activate_profile_in(&mut stx, &taira, [5; 32], &later).expect_err("Taira");
            // Versions may be skipped as long as they grow.
            activate_profile_in(&mut stx, &activation(3), [6; 32], &later).expect("version 3");
            assert_eq!(newest_profile_version(&*stx.world, network), 3);
            stx.apply();
        }
        {
            // A release that does not compile the version fails closed instead of refusing.
            let mut stx = block.transaction();
            let mut unknown = activation(3);
            unknown.version = 4;
            let error = activate_profile_in(&mut stx, &unknown, [7; 32], &release_with(3))
                .expect_err("version 4 is not compiled");
            assert!(error.to_string().contains("not applied"), "{error}");
            assert!(deferred(&stx));
        }
    }

    #[test]
    fn verification_switches_profiles_at_the_activation_height() {
        let state = blank_state();
        let network = SccpNetworkV1::EthereumMainnet;
        let later = release_with(2);
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        activate_profile_in(&mut stx, &activation(2), [4; 32], &later).expect("version 2");
        let genesis_hash = crate::state::sccp_genesis_policy_hash_v1();
        let world = &*stx.world;
        // Before the activation height the new release resolves exactly what the old one does,
        // so blocks from before the activation replay identically under it.
        let old_rules = SccpLcProfileCatalogV1::compiled()
            .resolve(&active_profiles_at(
                world,
                5,
                &SccpLcProfileCatalogV1::compiled(),
            ))
            .expect("version 1");
        let new_rules = later
            .resolve(&active_profiles_at(world, 5, &later))
            .expect("version 1");
        assert_eq!(old_rules, GENESIS_PROFILES);
        assert_eq!(new_rules, old_rules);
        assert_eq!(crate::state::sccp_policy_hash_v1(world, 5), genesis_hash);
        // From the activation height the new release verifies under version 2 and the digest
        // commits to it; the old release cannot resolve it and fails closed.
        let switched = later
            .resolve(&active_profiles_at(world, 6, &later))
            .expect("version 2");
        assert_eq!(switched.ethereum, LATER_ETHEREUM[1]);
        assert_ne!(switched, GENESIS_PROFILES);
        assert_ne!(crate::state::sccp_policy_hash_v1(world, 6), genesis_hash);
        assert_eq!(
            ensure_profiles_compiled(world, 6),
            Err(SccpLcProfileUnavailableV1::NotCompiled {
                network,
                version: 2
            })
        );
        assert_eq!(ensure_profiles_compiled(world, 5), Ok(()));
        let reject = admission_profiles(world, 6).expect_err("not compiled");
        assert!(reject.reason.contains("does not compile"), "{reject}");
        assert_eq!(admission_profiles(world, 5), Ok(GENESIS_PROFILES));
    }

    #[test]
    fn compiling_a_version_without_activating_it_keeps_the_digest() {
        let state = blank_state();
        let view = state.world_view();
        for height in [1, 1_000] {
            let old_release = active_profiles_at(&view, height, &release_with(1));
            let new_release = active_profiles_at(&view, height, &release_with(3));
            assert_eq!(old_release, new_release);
            assert_eq!(old_release.policy_hash(), new_release.policy_hash());
            assert_eq!(
                crate::state::sccp_policy_hash_v1(&view, height),
                crate::state::sccp_genesis_policy_hash_v1()
            );
        }
    }

    #[test]
    fn executing_under_an_uncompiled_active_version_defers_the_block() {
        let state = blank_state();
        let network = SccpNetworkV1::EthereumMainnet;
        let mut block = state.block(header(6));
        // Version 2, recorded by a release that compiles it, active from this block.
        let record = |stx: &mut StateTransaction<'_, '_>| {
            store::light_client_profiles::insert(
                stx,
                (network, 2),
                SccpLcProfileActivationV1 {
                    profile_hash: LATER_ETHEREUM[1].profile_hash(),
                    activation_height: 6,
                    proposal_id: [4; 32],
                },
            )
            .expect("record");
        };
        {
            let mut stx = block.transaction();
            record(&mut stx);
            let profiles = executing_profiles_in(&mut stx, &release_with(2)).expect("compiled");
            assert_eq!(profiles.ethereum, LATER_ETHEREUM[1]);
            assert!(!deferred(&stx));
        }
        {
            let mut stx = block.transaction();
            record(&mut stx);
            let error = executing_profiles(&mut stx).expect_err("this release lacks version 2");
            assert!(error.to_string().contains("not applied"), "{error}");
            assert!(deferred(&stx));
        }
        {
            // A verifier entry point fails closed rather than refusing the action.
            let mut stx = block.transaction();
            record(&mut stx);
            let action = SccpInitializeLightClientActionV1 {
                network,
                expected: iroha_data_model::sccp::light_client::SccpLcInitExpectationV1::Absent,
                params:
                    iroha_data_model::sccp::light_client::SccpLightClientParamsV1::defaults_for(
                        network,
                    )
                    .expect("ethereum defaults"),
                bootstrap: iroha_data_model::sccp::light_client::SccpLcBootstrapV1 {
                    network,
                    bytes: vec![1, 2, 3],
                },
            };
            initialize(&mut stx, &action, [1; 32]).expect_err("deferred");
            assert!(deferred(&stx));
        }
        {
            // Without the activation version 1 applies and the malformed bootstrap is refused.
            let mut stx = block.transaction();
            initialize(
                &mut stx,
                &SccpInitializeLightClientActionV1 {
                    network,
                    expected: iroha_data_model::sccp::light_client::SccpLcInitExpectationV1::Absent,
                    params:
                        iroha_data_model::sccp::light_client::SccpLightClientParamsV1::defaults_for(
                            network,
                        )
                        .expect("ethereum defaults"),
                    bootstrap: iroha_data_model::sccp::light_client::SccpLcBootstrapV1 {
                        network,
                        bytes: vec![1, 2, 3],
                    },
                },
                [1; 32],
            )
            .expect_err("malformed bootstrap");
            assert!(!deferred(&stx), "a deterministic refusal, not a deferral");
        }
    }

    #[test]
    fn trusted_checkpoints_and_freezes_need_an_installed_light_client() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        let action = SccpInstallTrustedCheckpointActionV1 {
            network,
            checkpoint: checkpoint(5, SccpLcCheckpointOriginV1::Parliament).data,
        };
        install_checkpoint(&mut stx, &action, [1; 32]).expect_err("not installed");
        // TON is refused before anything else: it records no checkpoints.
        let ton = SccpNetworkV1::TonMainnet;
        let error = install_checkpoint(
            &mut stx,
            &SccpInstallTrustedCheckpointActionV1 {
                network: ton,
                ..action.clone()
            },
            [1; 32],
        )
        .expect_err("TON reads no checkpoints");
        assert!(
            error.to_string().contains("reads no checkpoints"),
            "{error}"
        );
        assert!(!deferred(&stx), "a deterministic refusal, not a deferral");
        assert_eq!(
            store::light_client_checkpoints::get(&*stx.world, &(ton, 5)),
            None
        );
        freeze(
            &mut stx,
            &SccpFreezeLightClientActionV1 { network },
            [1; 32],
        )
        .expect_err("not installed");

        store::light_clients::insert(&mut stx, network, installed(100)).expect("installed");
        record_checkpoint(
            &mut stx,
            network,
            checkpoint(5, SccpLcCheckpointOriginV1::Advance),
        )
        .expect("checkpoint");
        install_checkpoint(&mut stx, &action, [1; 32]).expect("same block upgrades");
        assert_eq!(
            store::light_client_checkpoints::get(&*stx.world, &(network, 5)).map(|c| c.origin),
            Some(SccpLcCheckpointOriginV1::Parliament)
        );
        let mut conflicting = action.clone();
        conflicting.checkpoint.block_hash = [9; 32];
        install_checkpoint(&mut stx, &conflicting, [2; 32]).expect_err("conflict");

        freeze(
            &mut stx,
            &SccpFreezeLightClientActionV1 { network },
            [7; 32],
        )
        .expect("freeze");
        let frozen = *store::light_clients::get(&*stx.world, &network).expect("installed");
        assert!(frozen.is_frozen());
        assert_ne!(frozen.state_hash, installed(100).state_hash);
        freeze(
            &mut stx,
            &SccpFreezeLightClientActionV1 { network },
            [8; 32],
        )
        .expect("idempotent");
        assert_eq!(
            *store::light_clients::get(&*stx.world, &network).expect("installed"),
            frozen
        );
        assert!(!is_usable(
            &*stx.world,
            SccpChainProfilesV1::genesis(),
            network,
            0
        ));
    }
}
