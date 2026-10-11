//! Offline, authenticated and atomic publication of current plus pending beacon custody.

use super::*;
use crate::beacon_bootstrap::{Directory, FinalityLimitsArgs, read_public_bytes_bounded};
use clap::Parser;
use iroha_core::sumeragi::native_journal::NativeJournalError;
use iroha_core::validator_committee_evidence::{
    COMMITTEE_PROVISIONING_EVIDENCE_MAX_BYTES_V1, ValidatorCommitteeProvisioningEvidenceError,
    ValidatorCommitteeProvisioningEvidenceV1, verify_validator_committee_provisioning_evidence_v1,
};
use iroha_crypto::Hash;
use iroha_model_base::chain::ChainId;
use iroha_model_base::peer::PeerId;
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};

const CATALOG: &str = "runtime-provider-catalog.norito";
const RECEIPT: &str = "pending-beacon-custody.json";
const FILES: [&str; 3] = [
    GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1,
    CATALOG,
    RECEIPT,
];

#[derive(Parser)]
#[command(
    name = "beacon-prepare-custody",
    about = "Prepare authenticated pending beacon custody; never activates a session or submits a transaction"
)]
struct Args {
    /// Canonical public evidence exported by `iroha staking committee export-custody-evidence`.
    #[arg(long)]
    evidence: PathBuf,
    /// Independently supplied genesis-derived checked network identity.
    #[arg(long)]
    network_id: NetworkId,
    /// Explicit bounds for source bytes and cumulative decoded allocation.
    #[command(flatten)]
    finality_limits: FinalityLimitsArgs,
    /// Required aggregate local custody budget; must match a retained catalog exactly.
    #[arg(long)]
    credential_max_memory_bytes: std::num::NonZeroUsize,
    #[arg(long)]
    target_epoch: u64,
    /// Exact frozen attempt identifier, as 64 hexadecimal digits.
    #[arg(long)]
    transition_id: String,
    #[arg(long)]
    local_validator: PeerId,
    #[arg(long)]
    chain_id: String,
    #[arg(long)]
    handle: String,
    #[arg(long)]
    revision: u64,
    /// Canonical current public catalog; its private beacon frame is inherited on FD 200.
    #[arg(long)]
    current_catalog: Option<PathBuf>,
    /// New immutable generation directory under an existing secure absolute parent.
    #[arg(long)]
    output: PathBuf,
}

#[derive(norito::derive::JsonSerialize)]
struct Receipt {
    schema: String,
    network_id: NetworkId,
    transition_id: [u8; 32],
    target_epoch: u64,
    local_validator: PeerId,
    observed_height: u64,
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    revision: u64,
    policy_digest: [u8; 32],
    credential_hash: Hash,
    catalog_hash: Hash,
}

pub(crate) fn dispatch_if_requested() -> bool {
    let mut args = std::env::args_os();
    let _ = args.next();
    if args.next().as_deref() != Some(OsStr::new("beacon-prepare-custody")) {
        return false;
    }
    let args =
        Args::parse_from(std::iter::once(OsString::from("beacon-prepare-custody")).chain(args));
    if let Err(error) = run(args) {
        eprintln!("beacon custody preparation failed: {error}");
        std::process::exit(1);
    }
    true
}

/// Preserve local admission failures until the terminal command diagnostic.
#[derive(Debug)]
enum PreparationError {
    Invalid(&'static str),
    Journal(NativeJournalError),
    Evidence(ValidatorCommitteeProvisioningEvidenceError),
    Credential(RuntimeConsensusThresholdSignerCredentialErrorV1),
}
impl From<NativeJournalError> for PreparationError {
    fn from(error: NativeJournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<&'static str> for PreparationError {
    fn from(reason: &'static str) -> Self {
        Self::Invalid(reason)
    }
}
impl From<ValidatorCommitteeProvisioningEvidenceError> for PreparationError {
    fn from(error: ValidatorCommitteeProvisioningEvidenceError) -> Self {
        Self::Evidence(error)
    }
}
impl From<RuntimeConsensusThresholdSignerCredentialErrorV1> for PreparationError {
    fn from(error: RuntimeConsensusThresholdSignerCredentialErrorV1) -> Self {
        Self::Credential(error)
    }
}
impl From<GlobalThresholdBeaconSessionError> for PreparationError {
    fn from(error: GlobalThresholdBeaconSessionError) -> Self {
        Self::Credential(error.into())
    }
}
impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => formatter.write_str(reason),
            Self::Journal(error) => fmt::Display::fmt(error, formatter),
            Self::Credential(error) => fmt::Display::fmt(error, formatter),
            Self::Evidence(error) => fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Journal(error) => Some(error),
            Self::Credential(error) => Some(error),
            Self::Evidence(error) => Some(error),
        }
    }
}

fn decode_provisioning_evidence(
    bytes: &[u8],
    limits: iroha_data_model::sumeragi::finality::NativeFinalityLimits,
) -> Result<ValidatorCommitteeProvisioningEvidenceV1, PreparationError> {
    let admission = limits
        .decode_limits()
        .map_err(|_| "invalid finality admission limits")?;
    // TODO: source bytes and the outer evidence DTO need retained caller-pool ledgers;
    // canonical counter admission and typed source errors alone do not fund that graph.
    norito::core::with_decode_limits_scope(admission, || {
        norito::decode_canonical_for_admission(bytes, norito::canonical_decode_limits(bytes.len()))
            .map_err(iroha_data_model::sumeragi::finality::NativeFinalityDecodeError::from)
            .map_err(NativeJournalError::Decode)
            .map_err(PreparationError::Journal)
    })
}

fn run(args: Args) -> Result<(), PreparationError> {
    let limits = args
        .finality_limits
        .checked()
        .map_err(|_| "invalid finality admission limits")?;
    let chain_id: ChainId = args
        .chain_id
        .parse()
        .map_err(|_| "invalid chain identifier")?;
    let credential_max_memory_bytes = args.credential_max_memory_bytes.get();
    let credential_budget = AllocationBudget::new(credential_max_memory_bytes);
    let transition_id: [u8; 32] = hex::decode(&args.transition_id)
        .map_err(|_| "invalid transition identifier")?
        .try_into()
        .map_err(|_| "invalid transition identifier")?;
    let evidence_bytes = read_public_bytes_bounded(
        &args.evidence,
        limits
            .journal_bytes
            .min(COMMITTEE_PROVISIONING_EVIDENCE_MAX_BYTES_V1),
    )
    .map_err(|_| "untrusted evidence file")?;
    let evidence = decode_provisioning_evidence(&evidence_bytes, limits)?;
    let verified = verify_validator_committee_provisioning_evidence_v1(
        &evidence,
        &chain_id,
        args.network_id,
        args.target_epoch,
        transition_id,
        limits,
        &credential_budget,
    )?;
    // No private descriptor is opened until every public authorization and target binding passes.
    let catalog = args
        .current_catalog
        .as_ref()
        .map(|path| {
            let bytes = read_public_bytes_bounded(
                path,
                crate::runtime_provider_registry::RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1,
            )
            .map_err(|_| "untrusted retained catalog")?;
            IrohaRuntimeProviderBindingsV1::load_canonical_v1(&bytes)
                .map_err(|_| "invalid retained catalog")
        })
        .transpose()?;
    if catalog.as_ref().is_some_and(|value| {
        value.network_id() != &args.network_id || value.chain_id() != args.chain_id
    }) {
        return Err("retained catalog network or chain differs".into());
    }
    if catalog
        .as_ref()
        .is_some_and(|catalog| catalog.credential_max_memory_bytes() != credential_max_memory_bytes)
    {
        return Err("retained catalog credential memory bound differs".into());
    }
    let binding = catalog.as_ref().and_then(|catalog| {
        catalog
            .iter()
            .find(|entry| entry.slot() == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner)
    });
    let incumbent_index = verified
        .incumbent_authority()
        .validators
        .iter()
        .position(|seat| seat == &args.local_validator)
        .map(|index| u16::try_from(index + 1).map_err(|_| "invalid incumbent index"))
        .transpose()?;
    if incumbent_index.is_some() && binding.is_none() {
        return Err("incumbent validator must retain its exact current credential".into());
    }
    if args.current_catalog.is_some() && binding.is_none() {
        return Err("retained catalog lacks a qualified beacon slot".into());
    }
    let target_index = verified
        .transition()
        .preparation
        .committee
        .iter()
        .position(|seat| seat.validator == args.local_validator)
        .map(|index| u16::try_from(index + 1).map_err(|_| "invalid target index"))
        .transpose()?
        .ok_or("validator is not a frozen target seat")?;
    let output_parent = args
        .output
        .parent()
        .ok_or("output requires an absolute secure parent")?;
    let parent = Directory::open(output_parent).map_err(|_| "untrusted output parent")?;
    let output_name = args.output.file_name().ok_or("invalid output name")?;
    let retained = binding
        .map(|_| {
            let file = crate::taira_runtime_signer::take_inherited_private_file(200)
                .map_err(|_| "retained credential FD 200 unavailable")?;
            read_retained_frame(file)
        })
        .transpose()?;
    let retained_shares = retained
        .as_deref()
        .zip(binding)
        .map(|(bytes, binding)| {
            decode_global_beacon_credential_shares_v1(
                bytes,
                &args.network_id,
                binding,
                &credential_budget,
            )
            .map(|shares| (shares, binding))
        })
        .transpose()?;
    if let Some((shares, _)) = retained_shares.as_ref() {
        validate_retained_incumbent(shares, incumbent_index, verified.incumbent_beacon())?;
    }
    // Verification retained this exact graph in the same operation pool.
    let pending_session = verified.session().clone();
    let share_file = crate::taira_runtime_signer::take_inherited_private_file(198)
        .map_err(|_| "pending share FD 198 unavailable")?;
    let components =
        crate::taira_runtime_signer::load_private_record_from_file(share_file, 96, |bytes| {
            let mut components = Zeroizing::new([[0; 32]; 3]);
            for (component, bytes) in components.iter_mut().zip(bytes.chunks_exact(32)) {
                component.copy_from_slice(bytes);
            }
            Ok(components)
        })
        .map_err(|_| "invalid disposable pending share descriptor")?;
    let prepared = prepared::prepare_global_beacon_transition_from_retained_v1(
        retained_shares
            .as_ref()
            .map(|(shares, binding)| (shares.as_slice(), *binding)),
        &args.handle,
        args.revision,
        verified.transition(),
        &args.local_validator,
        &RuntimeGlobalBeaconShareProvisioningV1::new(pending_session, target_index, components),
        &credential_budget,
    )?;
    let catalog = IrohaRuntimeProviderBindingsV1::with_prepared_beacon_inventory_v1(
        catalog.as_ref(),
        &args.chain_id,
        args.network_id,
        &args.handle,
        prepared.revision,
        prepared.policy_digest,
        credential_max_memory_bytes,
    )
    .map_err(|_| "invalid advanced catalog qualification")?
    .export_canonical_v1()
    .map_err(|_| "catalog encoding failed")?;
    let receipt = norito::json::to_vec(&Receipt {
        schema: "iroha.pending-beacon-custody.v1".to_owned(),
        network_id: args.network_id,
        transition_id,
        target_epoch: args.target_epoch,
        local_validator: args.local_validator,
        observed_height: verified.observed_height(),
        session_id: verified.session().session_id,
        transcript_hash: verified.session().transcript_hash,
        revision: prepared.revision,
        policy_digest: prepared.policy_digest,
        credential_hash: Hash::new(prepared.credential.as_slice()),
        catalog_hash: Hash::new(&catalog),
    })
    .map_err(|_| "receipt encoding failed")?;
    publish_generation(
        &parent,
        output_name,
        &prepared.credential,
        &catalog,
        &receipt,
    )?;
    println!(
        "Pending custody prepared at {}; no session activated",
        args.output.display()
    );
    Ok(())
}

pub(super) fn validate_retained_incumbent(
    retained: &[RuntimeGlobalBeaconShareProvisioningV1],
    incumbent_index: Option<u16>,
    active: iroha_data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1,
) -> Result<(), &'static str> {
    if let Some(index) = incumbent_index {
        if !retained.iter().any(|entry| {
            entry.signer_index() == index
                && entry.public_session().session_id == active.session_id
                && entry.public_session().transcript_hash == active.transcript_hash
        }) {
            return Err("retained credential omits exact incumbent session custody");
        }
    }
    Ok(())
}

fn read_retained_frame(mut file: File) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let before = file
        .metadata()
        .map_err(|_| "retained credential metadata unavailable")?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() == 0
        || before.len() > MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1 as u64
    {
        return Err("untrusted retained credential descriptor");
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "retained credential seek failed")?;
    let length = usize::try_from(before.len()).map_err(|_| "retained credential size invalid")?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "retained credential allocation failed")?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| "retained credential read failed")?;
    let mut extra = Zeroizing::new([0; 1]);
    let count = file
        .read(extra.as_mut())
        .map_err(|_| "retained credential trailing read failed")?;
    let after = file
        .metadata()
        .map_err(|_| "retained credential metadata unavailable")?;
    if count != 0
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("retained credential changed during read");
    }
    Ok(bytes)
}

fn publish_generation(
    parent: &Directory,
    name: &OsStr,
    credential: &[u8],
    catalog: &[u8],
    receipt: &[u8],
) -> Result<(), &'static str> {
    let stage_name = format!(
        ".pending-beacon-{}-{}",
        std::process::id(),
        Hash::new(catalog)
    );
    let staging = parent
        .child(OsStr::new(&stage_name))
        .map_err(|_| "cannot create exclusive staging directory")?;
    let result = (|| {
        staging.write_new(OsStr::new(FILES[0]), credential, true)?;
        staging.write_new(OsStr::new(FILES[1]), catalog, false)?;
        staging.write_new(OsStr::new(FILES[2]), receipt, false)?;
        parent.publish_child(&staging, name)
    })();
    if result.is_err() {
        parent.discard_child(&staging, &FILES);
    }
    result.map_err(|_| "atomic generation publication failed; incumbent generation is unchanged")
}

#[cfg(test)]
#[path = "provisioning_command_tests.rs"]
mod tests;
