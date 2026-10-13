//! Same-State provider admission heads, immutable history and authenticated current lookup.

mod originals;
pub use originals::with_genesis_provider_admission_originals_v1;

use crate::{
    query::signer_finality::verify_signer_finality_v1,
    state::{StateReadOnly, WorldReadOnly},
    sumeragi::certified_chain::committed_block,
};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    provider_admission::{
        ProviderAdmissionCouncilPolicyV1,
        governance::{PROVIDER_ADMISSION_MAX_REVISIONS_V1, decode_frame},
    },
};
use mv::storage::StorageReadOnly;
use sorafs_manifest::{
    AdmissionRecord, ProviderAdmissionCouncilPolicy, ProviderAdmissionEnvelopeV1,
};

/// Native admission is unavailable, malformed, stale or not finalized at this exact State cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("native provider admission unavailable")]
pub struct ProviderAdmissionErrorV1;
pub(crate) type Error = ProviderAdmissionErrorV1;

pub(crate) use iroha_data_model::sorafs::provider_admission::history::{
    AdmissionHistoryPathV1, AdmissionHistoryRecordV1, GenesisAdmissionOriginV1,
    admission_history_path as path,
};

pub(crate) fn encode<T: norito::core::NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    iroha_data_model::sorafs::provider_admission::history::encode_history_value(value)
        .map_err(|_| ProviderAdmissionErrorV1)
}
pub(crate) fn digest(record: &AdmissionHistoryRecordV1) -> Result<[u8; 32], Error> {
    record
        .canonical_digest()
        .map_err(|_| ProviderAdmissionErrorV1)
}
fn decode_record(bytes: &[u8]) -> Result<AdmissionHistoryRecordV1, Error> {
    AdmissionHistoryRecordV1::decode_frame(bytes).map_err(|_| ProviderAdmissionErrorV1)
}
pub(crate) fn read_head(
    world: &impl WorldReadOnly,
    subject: Option<ProviderId>,
) -> Result<Option<AdmissionHistoryRecordV1>, Error> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&path(subject, AdmissionHistoryPathV1::Head))
    else {
        return Ok(None);
    };
    let head = decode_record(bytes)?;
    if head.revision == 0
        || head.revision > PROVIDER_ADMISSION_MAX_REVISIONS_V1
        || head.height == 0
        || head.recorded_at_unix_ms == 0
        || head.network_id == [0; 32]
        || (head.genesis_origin.is_some() && (head.height != 1 || head.revision != 1))
        || (head.revision == 1) != head.predecessor.is_none()
    {
        return Err(ProviderAdmissionErrorV1);
    }
    let retained = world
        .smart_contract_state()
        .get(&path(
            subject,
            AdmissionHistoryPathV1::Revision(head.revision),
        ))
        .ok_or(ProviderAdmissionErrorV1)?;
    if retained != bytes
        || world
            .smart_contract_state()
            .get(&path(
                subject,
                AdmissionHistoryPathV1::Revision(head.revision + 1),
            ))
            .is_some()
    {
        return Err(ProviderAdmissionErrorV1);
    }
    if let Some(expected) = head.predecessor {
        let previous = world
            .smart_contract_state()
            .get(&path(
                subject,
                AdmissionHistoryPathV1::Revision(head.revision - 1),
            ))
            .ok_or(ProviderAdmissionErrorV1)?;
        let previous = decode_record(previous)?;
        if digest(&previous)? != expected
            || previous.revision + 1 != head.revision
            || previous.network_id != head.network_id
            || previous.height > head.height
            || previous.recorded_at_unix_ms > head.recorded_at_unix_ms
            || previous.revoked
        {
            return Err(ProviderAdmissionErrorV1);
        }
    }
    Ok(Some(head))
}
pub(crate) fn read_policy(
    world: &impl WorldReadOnly,
) -> Result<Option<ProviderAdmissionCouncilPolicyV1>, Error> {
    read_head(world, None)?
        .map(|head| {
            let policy: ProviderAdmissionCouncilPolicyV1 =
                decode_frame(&head.material).map_err(|_| ProviderAdmissionErrorV1)?;
            policy.validate().map_err(|_| ProviderAdmissionErrorV1)?;
            if policy.revision != head.revision
                || policy.network_id != head.network_id
                || head.revoked
                || head.owner.is_some()
            {
                return Err(ProviderAdmissionErrorV1);
            }
            Ok(policy)
        })
        .transpose()
}
pub(crate) fn council(
    policy: &ProviderAdmissionCouncilPolicyV1,
) -> Result<ProviderAdmissionCouncilPolicy, Error> {
    ProviderAdmissionCouncilPolicy::new(
        policy.trusted_signers.iter().copied(),
        usize::from(policy.signature_threshold),
    )
    .map_err(|_| ProviderAdmissionErrorV1)
}
fn active_record(
    view: &impl StateReadOnly,
    provider: ProviderId,
    policy: &ProviderAdmissionCouncilPolicyV1,
    now_secs: u64,
    expiry_time_secs: u64,
) -> Result<Option<AdmissionRecord>, Error> {
    let world = view.world();
    let Some(head) = read_head(world, Some(provider))? else {
        return Ok(None);
    };
    if head.revoked {
        return Ok(None);
    }
    if head.network_id != policy.network_id
        || head.owner.is_none()
        || head.owner.as_ref() != world.provider_owners().get(&provider)
    {
        return Err(ProviderAdmissionErrorV1);
    }
    let envelope: ProviderAdmissionEnvelopeV1 =
        decode_frame(&head.material).map_err(|_| ProviderAdmissionErrorV1)?;
    if envelope.proposal.provider_id != *provider.as_bytes()
        || envelope.admission_revision != head.revision
        // Preserve the local not-before check while a lagging local clock cannot undo
        // expiry already established by the authenticated current committed block.
        || now_secs < envelope.issued_at
        || expiry_time_secs >= envelope.retention_epoch
    {
        return Err(ProviderAdmissionErrorV1);
    }
    if head.revision > 1 {
        let previous = world
            .smart_contract_state()
            .get(&path(
                Some(provider),
                AdmissionHistoryPathV1::Revision(head.revision - 1),
            ))
            .ok_or(ProviderAdmissionErrorV1)?;
        let previous = decode_record(previous)?;
        let previous_envelope: ProviderAdmissionEnvelopeV1 =
            decode_frame(&previous.material).map_err(|_| ProviderAdmissionErrorV1)?;
        let previous_digest =
            sorafs_manifest::provider_admission::compute_envelope_digest(&previous_envelope)
                .map_err(|_| ProviderAdmissionErrorV1)?;
        if envelope.expected_current_event_digest != Some(previous_digest) {
            return Err(ProviderAdmissionErrorV1);
        }
    }
    if head.genesis_origin.is_some() {
        let material = authenticate_genesis_record(view, Some(provider), &head)?
            .ok_or(ProviderAdmissionErrorV1)?;
        if (envelope.policy_id, envelope.policy_revision) != (policy.policy_id, policy.revision)
            || envelope.policy_digest
                != policy
                    .canonical_digest()
                    .map_err(|_| ProviderAdmissionErrorV1)?
        {
            return Err(ProviderAdmissionErrorV1);
        }
        return AdmissionRecord::from_genesis_material(
            &material,
            policy.network_id,
            policy.policy_id,
            policy
                .canonical_digest()
                .map_err(|_| ProviderAdmissionErrorV1)?,
        )
        .map(Some)
        .map_err(|_| ProviderAdmissionErrorV1);
    }
    policy
        .verify_envelope_policy_claim(&envelope, now_secs)
        .map_err(|_| ProviderAdmissionErrorV1)?;
    let envelope_digest = sorafs_manifest::provider_admission::compute_envelope_digest(&envelope)
        .map_err(|_| ProviderAdmissionErrorV1)?;
    AdmissionRecord::from_retained_envelope(envelope, &council(policy)?, envelope_digest)
        .map(Some)
        .map_err(|_| ProviderAdmissionErrorV1)
}

/// Read one provider against the exact current State head and its certified Kura frame.
/// Absence/revocation returns `None`; stale, corrupt or unavailable authority fails closed.
/// Local time must satisfy issuance; expiry uses the later of local and finalized block time.
///
/// # Errors
///
/// Returns an error if the finalized source cannot be authenticated,
/// authoritative admission state is malformed or stale, or the active
/// policy or provider evidence fails network, time, or signature checks.
pub fn read_finalized_provider_admission_v1(
    view: &impl StateReadOnly,
    provider: ProviderId,
    now_secs: u64,
) -> Result<Option<AdmissionRecord>, Error> {
    authenticate_current(view)?;
    read_current_provider_admission(view, provider, now_secs)
}

fn read_current_provider_admission(
    view: &impl StateReadOnly,
    provider: ProviderId,
    now_secs: u64,
) -> Result<Option<AdmissionRecord>, Error> {
    let finalized_secs = view
        .authenticated_query_ledger_time_ms()
        .ok_or(ProviderAdmissionErrorV1)?
        / 1_000;
    let Some(policy) = read_policy(view.world())? else {
        return Ok(None);
    };
    if policy.network_id != *view.network_id().as_bytes() || policy.paused {
        return Err(ProviderAdmissionErrorV1);
    }
    if let Some(head) = read_head(view.world(), Some(provider))? {
        if head.height > view.block_hashes().len() as u64 {
            return Err(ProviderAdmissionErrorV1);
        }
    }
    active_record(
        view,
        provider,
        &policy,
        now_secs,
        now_secs.max(finalized_secs),
    )
}
/// Read the current admission through an already-authenticated native receipt from this exact view.
/// A same-height receipt from another view, or an older receipt from this view, is not current.
/// The caller retains the original cumulative native reader/decoder allowance around this call.
pub(crate) fn read_provider_admission_at_native_current_v1(
    view: &crate::state::StateView<'_>,
    current: &super::signer_check::SignerCertifiedBlockV1<'_, '_>,
    provider: ProviderId,
    now_secs: u64,
) -> Result<Option<AdmissionRecord>, Error> {
    let block = current
        .in_view(view)
        .map_err(|_| ProviderAdmissionErrorV1)?;
    if block.height() != view.height() as u64
        || Some(block.block_hash()) != view.block_hashes().last().copied()
    {
        return Err(ProviderAdmissionErrorV1);
    }
    authenticate_current_head(view)?;
    read_current_provider_admission(view, provider, now_secs)
}

fn authenticate_current(view: &impl StateReadOnly) -> Result<(), Error> {
    let height = u64::try_from(view.block_hashes().len()).map_err(|_| ProviderAdmissionErrorV1)?;
    let hash = view
        .block_hashes()
        .last()
        .map(|hash| *hash.as_ref())
        .ok_or(ProviderAdmissionErrorV1)?;
    verify_signer_finality_v1(view, height, hash).map_err(|_| ProviderAdmissionErrorV1)?;
    authenticate_current_head(view)
}

fn authenticate_current_head(view: &impl StateReadOnly) -> Result<(), Error> {
    let height = u64::try_from(view.block_hashes().len()).map_err(|_| ProviderAdmissionErrorV1)?;
    if let Some(head) = read_head(view.world(), None)? {
        if head.height > height {
            return Err(ProviderAdmissionErrorV1);
        }
        if head.genesis_origin.is_some() {
            authenticate_genesis_record(view, None, &head)?;
        }
    }
    Ok(())
}
/// Count permanent provider identities, including revocation tombstones, at a finalized cut.
///
/// # Errors
///
/// Returns an error if the finalized source cannot be authenticated, the
/// count cannot be decoded, or it exceeds the protocol provider bound.
pub fn retained_provider_count_v1(view: &impl StateReadOnly) -> Result<u64, Error> {
    authenticate_current(view)?;
    let count: u64 = view
        .world()
        .smart_contract_state()
        .get(&path(None, AdmissionHistoryPathV1::ProviderCount))
        .map(|bytes| decode_frame(bytes))
        .transpose()
        .map_err(|_| ProviderAdmissionErrorV1)?
        .unwrap_or(0);
    if count > iroha_data_model::sorafs::provider_admission::governance::PROVIDER_ADMISSION_MAX_PROVIDERS_V1 {
        return Err(ProviderAdmissionErrorV1);
    }
    Ok(count)
}
/// Preserve advert replay floors for admitted and permanently revoked native identities.
///
/// # Errors
///
/// Returns an error if the finalized source cannot be authenticated or the
/// provider history head is malformed.
pub fn retains_provider_identity_v1(
    view: &impl StateReadOnly,
    provider: ProviderId,
) -> Result<bool, Error> {
    authenticate_current(view)?;
    Ok(read_head(view.world(), Some(provider))?.is_some())
}
/// Read the current finalized council for dependent governance-signature validation.
///
/// # Errors
///
/// Returns an error if finalized authority or policy decoding fails, the
/// policy is paused or belongs to another network, or its council is invalid.
pub fn read_finalized_admission_council_v1(
    view: &impl StateReadOnly,
) -> Result<Option<ProviderAdmissionCouncilPolicy>, Error> {
    authenticate_current(view)?;
    read_policy(view.world())?
        .map(|policy| {
            if policy.network_id != *view.network_id().as_bytes() || policy.paused {
                return Err(ProviderAdmissionErrorV1);
            }
            council(&policy)
        })
        .transpose()
}

/// Authenticate the actual successful direct initializer in this State's exact signed genesis.
fn authenticate_genesis_record(
    view: &impl StateReadOnly,
    subject: Option<ProviderId>,
    head: &AdmissionHistoryRecordV1,
) -> Result<Option<sorafs_manifest::provider_admission::ProviderAdmissionGenesisMaterialV1>, Error>
{
    use iroha_data_model::{
        isi::sorafs::InitializeSorafsProviderAdmissionV1,
        transaction::{Executable, TransactionEntrypoint},
    };
    let invalid = ProviderAdmissionErrorV1;
    let origin = head.genesis_origin.as_ref().ok_or(invalid)?;
    if head.height != 1 || head.revision != 1 || head.predecessor.is_some() || head.revoked {
        return Err(invalid);
    }
    // The signed genesis is the chain's trust root: its frame's result-only certificate commits
    // its executed wire, which anchors the initializer's entry and output.
    let committed = committed_block(view, 1).map_err(|_| invalid)?;
    let genesis = committed.block();
    let hash = genesis.hash();
    if hash.as_ref() != view.network_id().as_bytes()
        || head.network_id != *view.network_id().as_bytes()
        || !genesis.header().is_genesis()
        || genesis.header().creation_time().as_millis() != u128::from(head.recorded_at_unix_ms)
    {
        return Err(invalid);
    }
    let entry = genesis
        .network_entrypoint_at(origin.entrypoint_index as usize)
        .ok_or(invalid)?;
    let TransactionEntrypoint::External(signed) = entry else {
        return Err(invalid);
    };
    if signed.network_id().is_some() {
        return Err(invalid);
    }
    signed.verify_signature().map_err(|_| invalid)?;
    let anchor = committed.entry_anchor(&entry.hash()).map_err(|_| invalid)?;
    if anchor.entry_index() != origin.entrypoint_index
        || !genesis
            .network_execution_proof(&entry.hash())
            .ok_or(invalid)?
            .verify(&anchor)
        || !genesis
            .network_output_at(origin.entrypoint_index)
            .ok_or(invalid)?
            .1
            .result
            .is_ok()
    {
        return Err(invalid);
    }
    let Executable::Instructions(instructions) = signed.instructions() else {
        return Err(invalid);
    };
    let mut matched = None;
    for instruction in instructions.iter() {
        let Some(initializer) = instruction
            .as_any()
            .downcast_ref::<InitializeSorafsProviderAdmissionV1>()
        else {
            continue;
        };
        if *iroha_crypto::Hash::new(norito::encode_canonical(initializer).map_err(|_| invalid)?)
            .as_ref()
            == origin.instruction_digest
        {
            if matched.is_some() {
                return Err(invalid);
            }
            matched = Some(initializer);
        }
    }
    let initializer = matched.ok_or(invalid)?;
    let policy = initializer
        .council
        .bind(*view.network_id().as_bytes())
        .map_err(|_| invalid)?;
    let Some(provider) = subject else {
        if head.owner.is_some() || head.material != encode(&policy)? {
            return Err(invalid);
        }
        return Ok(None);
    };
    let mut selected = None;
    for entry in &initializer.providers {
        let material: sorafs_manifest::provider_admission::ProviderAdmissionGenesisMaterialV1 =
            decode_frame(&entry.material).map_err(|_| invalid)?;
        if material.proposal.provider_id != *provider.as_bytes() {
            continue;
        }
        if selected.is_some() || head.owner.as_ref() != Some(&entry.owner) {
            return Err(invalid);
        }
        let projection = material
            .project(
                policy.network_id,
                policy.policy_id,
                policy.canonical_digest().map_err(|_| invalid)?,
            )
            .map_err(|_| invalid)?;
        if head.material != encode(&projection)? {
            return Err(invalid);
        }
        selected = Some(material);
    }
    selected.map(Some).ok_or(invalid)
}
