//! One public-original closure and one native allocation replay for CLI and installed consumers.

use super::*;
use std::collections::BTreeSet;

const SCHEMA: &str = "iroha.dataspace-authority-originals.v1";
const MAX_FILES: usize = 100_000;
const MAX_TOTAL: u64 = 8 * 1024 * 1024 * 1024;
const FIXED: [&str; 9] = [
    "definition.json",
    "plan.json",
    "catalog.prepared.json",
    "catalog.submitted.json",
    "bootstrap.prepared.json",
    "bootstrap.submitted.json",
    "aliases.prepared.json",
    "aliases.submitted.json",
    "trust-original.json",
];

/// Credential-free local replay of retained completed allocation originals.
#[derive(Debug, clap::Args)]
pub(crate) struct VerifyAuthority {
    /// Direct current-owner private bundle directory, with its original inventory.
    #[arg(long)]
    bundle: PathBuf,
    /// Independently selected original public genesis and four-peer trust profile.
    #[arg(long)]
    trust: PathBuf,
    /// Target ledger commit selected from separately authenticated signed source.
    #[arg(long)]
    source_commit: String,
    /// Target package version from the same separately authenticated signed source.
    #[arg(long)]
    source_version: String,
    /// Fresh result file under an existing private directory; saved results are not authority.
    #[arg(long)]
    output: PathBuf,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Inventory {
    schema: String,
    operation_id: String,
    intent_sha256: String,
    completion_file: String,
    original_trust_file: String,
    effective_trust_file: String,
    source_commit: String,
    source_version: String,
    files: Vec<FileRow>,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FileRow {
    path: String,
    size_bytes: String,
    sha256: String,
}

fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decimal(value: &str) -> Result<u64> {
    let parsed: u64 = value.parse()?;
    require(
        parsed.to_string() == value,
        "authority integer is not canonical decimal",
    )?;
    Ok(parsed)
}
fn carrier(name: &str) -> bool {
    name.strip_prefix("carrier-")
        .and_then(|n| n.strip_suffix(".nrt"))
        .is_some_and(|n| n.len() == 20 && n.bytes().all(|b| b.is_ascii_digit()))
}
fn bound(name: &str) -> usize {
    if carrier(name) {
        iroha_data_model::block::proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1
    } else {
        MAX_BYTES
    }
}
fn canonical<T: JsonSerialize + JsonDeserialize>(bytes: &[u8]) -> Result<T> {
    let value = json::from_slice(bytes)?;
    require(
        json::to_vec(&value)? == bytes,
        "allocation original is noncanonical or incomplete",
    )?;
    Ok(value)
}
impl Inventory {
    fn decode(bytes: &[u8]) -> Result<Self> {
        require(
            bytes.len() <= MAX_BYTES,
            "authority inventory exceeds bound",
        )?;
        let value: Self = canonical(bytes)?;
        operation_id(&value.operation_id)?;
        require(
            value.schema == SCHEMA
                && lowercase_hex(&value.intent_sha256, 64)
                && value.original_trust_file == "trust-original.json"
                && !value.files.is_empty()
                && value.files.len() <= MAX_FILES,
            "authority inventory identity differs",
        )?;
        let mut total = 0u64;
        let mut previous: Option<&str> = None;
        for row in &value.files {
            require(
                !row.path.is_empty()
                    && row.path.len() <= 128
                    && row
                        .path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                    && row.path != "lock"
                    && row.path != "authority.json"
                    && !row.path.starts_with('.')
                    && previous.is_none_or(|p| p < row.path.as_str())
                    && lowercase_hex(&row.sha256, 64),
                "authority file inventory is not direct, unique and sorted",
            )?;
            let size = decimal(&row.size_bytes)?;
            require(
                size > 0 && size <= bound(&row.path) as u64,
                "authority original size exceeds bound",
            )?;
            total = total
                .checked_add(size)
                .ok_or_else(|| eyre!("authority total size overflow"))?;
            previous = Some(&row.path);
        }
        require(
            total <= MAX_TOTAL,
            "authority original closure exceeds total bound",
        )?;
        Ok(value)
    }
}

/// One bounded direct original selected by an authority inventory. This is
/// inspection data only; it carries no signature, finality or allocation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataspaceAuthorityOriginal {
    path: String,
    size_bytes: u64,
    sha256: String,
}
impl DataspaceAuthorityOriginal {
    /// One direct filename, without a directory, traversal or filesystem lock.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Exact bounded byte count, decoded from canonical decimal text without rounding.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    /// Exact lowercase whole-original SHA-256 selected by the untrusted inventory.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Inspect the same bounded canonical inventory used by the genuine replay entry.
///
/// This allows an installed caller to obtain the exact original filenames before
/// loading their bytes. No original hash, trust, source, signature, execution or
/// finality is authenticated by inspection; callers must subsequently invoke
/// [`verify_dataspace_authority_originals`] with independently selected authority.
///
/// # Errors
/// Rejects malformed/unknown fields, noncanonical identities or integer syntax,
/// indirect/duplicate/unordered filenames, and per-original/aggregate resource limits.
pub fn dataspace_authority_original_inventory(
    authority: &[u8],
) -> Result<Vec<DataspaceAuthorityOriginal>> {
    Inventory::decode(authority)?
        .files
        .into_iter()
        .map(|row| {
            Ok(DataspaceAuthorityOriginal {
                path: row.path,
                size_bytes: decimal(&row.size_bytes)?,
                sha256: row.sha256,
            })
        })
        .collect()
}

/// Read the inventory's exact completion-original digest through the same Native
/// decoder. This is a bounded inspection join, never finality or allocation proof.
///
/// # Errors
/// Rejects a malformed inventory, a noncanonical/nonzero-challenge completion
/// filename, or a completion original missing from the exact direct inventory.
pub fn dataspace_authority_completion_sha256(authority: &[u8]) -> Result<String> {
    let inventory = Inventory::decode(authority)?;
    let challenge = inventory
        .completion_file
        .strip_prefix("completion-")
        .and_then(|name| name.strip_suffix(".json"))
        .ok_or_else(|| eyre!("authority completion filename differs"))?;
    require(
        lowercase_hex(challenge, 64) && challenge.bytes().any(|b| b != b'0'),
        "authority completion challenge differs",
    )?;
    inventory
        .files
        .into_iter()
        .find(|row| row.path == inventory.completion_file)
        .map(|row| row.sha256)
        .ok_or_else(|| eyre!("authority inventory omits completion original"))
}

/// Invocation-owned proof that exact originals authenticate a completed allocation.
/// This value has no public constructor or deserializer. Source signatures and live
/// host readiness are separate authorities and are never inferred from this token.
#[derive(Debug)]
pub struct VerifiedDataspaceAuthority {
    network: NetworkId,
    owner: AccountId,
    dataspace: u64,
    lane: u32,
    namespace: String,
    source_commit: String,
    source_version: String,
    operation_id: String,
    intent_sha256: String,
    authority_sha256: String,
    trust_profile_sha256: String,
    completion_sha256: String,
    projection: json::Value,
}
impl VerifiedDataspaceAuthority {
    /// Independently genesis-bound network identity.
    pub fn network_id(&self) -> NetworkId {
        self.network
    }
    /// Exact signer and owner of the successful allocation transactions.
    pub fn owner(&self) -> &AccountId {
        &self.owner
    }
    /// Lossless native numeric dataspace identity.
    pub fn dataspace_id(&self) -> u64 {
        self.dataspace
    }
    /// Exact physical lane selected by the successful catalog transaction.
    pub fn lane_id(&self) -> u32 {
        self.lane
    }
    /// Directly allocated paid namespace; no application domain is invented.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    /// Target commit joined to the signed peer build attestations.
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    /// Target version joined to the signed peer build attestations.
    pub fn source_version(&self) -> &str {
        &self.source_version
    }
    /// Exact original allocation operation identity.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    /// Canonical intent digest bound by every successful phase.
    pub fn intent_sha256(&self) -> &str {
        &self.intent_sha256
    }
    /// Whole-byte digest of the exact original authority inventory.
    pub fn authority_sha256(&self) -> &str {
        &self.authority_sha256
    }
    /// Whole-byte digest of the independently selected original public trust.
    pub fn trust_profile_sha256(&self) -> &str {
        &self.trust_profile_sha256
    }
    /// Whole-byte digest of the exact completion original replayed by this invocation.
    pub fn completion_sha256(&self) -> &str {
        &self.completion_sha256
    }
    /// Verified diagnostic projection for this invocation; never a replayable credential.
    pub fn projection(&self) -> &json::Value {
        &self.projection
    }
    /// Serialize the verified diagnostic projection with lossless decimal IDs and heights.
    pub fn projection_bytes(&self) -> Result<Vec<u8>> {
        Ok(json::to_vec(&self.projection)?)
    }
}

/// Authenticate completed allocation originals using the same native routine as the CLI.
///
/// `authority` is the whole original authority.json; `originals` must contain exactly
/// its inventoried direct files, without authority.json or the filesystem lock. Trust,
/// target commit and version must be selected independently by the caller. The caller
/// retains source-signature/tree admission and immutable original custody. This routine
/// performs no filesystem, network, signing, account-key or host-process operations.
///
/// # Errors
/// Rejects malformed or incomplete inventories, changed originals, foreign trust or
/// source, invalid signatures/finality, and failed or mismatched allocation execution.
pub fn verify_dataspace_authority_originals(
    authority: &[u8],
    originals: &BTreeMap<String, Vec<u8>>,
    independent_trust: &[u8],
    target_commit: &str,
    target_version: &str,
) -> Result<VerifiedDataspaceAuthority> {
    let inventory = Inventory::decode(authority)?;
    require(
        originals.len() == inventory.files.len()
            && inventory
                .files
                .iter()
                .all(|f| originals.contains_key(&f.path)),
        "authority byte map differs from exact inventory",
    )?;
    verify(
        authority,
        &inventory,
        independent_trust,
        target_commit,
        target_version,
        |name, maximum| {
            let bytes = originals
                .get(name)
                .ok_or_else(|| eyre!("missing authority original"))?;
            require(
                bytes.len() <= maximum,
                "authority original exceeds reader bound",
            )?;
            Ok(bytes.clone())
        },
    )
}

fn verify(
    authority_bytes: &[u8],
    inventory: &Inventory,
    independent_trust: &[u8],
    target_commit: &str,
    target_version: &str,
    mut read_original: impl FnMut(&str, usize) -> Result<Vec<u8>>,
) -> Result<VerifiedDataspaceAuthority> {
    let fingerprint = runtime_update::selected_source_fingerprint(target_commit, target_version)?;
    require(
        inventory.source_commit == target_commit && inventory.source_version == target_version,
        "allocation authority target source differs from independent selection",
    )?;
    require(
        independent_trust.len() <= MAX_BYTES,
        "independent trust exceeds bound",
    )?;
    let original: DeploymentTrustV1 = json::from_slice(independent_trust)?;
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        original.account_chain_discriminant,
    );
    let entries = inventory
        .files
        .iter()
        .map(|r| (r.path.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    let mut consumed = BTreeSet::new();
    let mut read = |name: &str, maximum: usize| -> Result<Vec<u8>> {
        let row = entries
            .get(name)
            .ok_or_else(|| eyre!("authority inventory omits required original"))?;
        let bytes = read_original(name, maximum.min(bound(name)))?;
        require(
            bytes.len() as u64 == decimal(&row.size_bytes)? && digest(&bytes) == row.sha256,
            "authority original changed from inventory",
        )?;
        consumed.insert(name.to_owned());
        Ok(bytes)
    };
    require(
        read("trust-original.json", MAX_BYTES)? == independent_trust,
        "exported trust differs from independently selected original bytes",
    )?;
    let plan: PlanV1 = canonical(&read("plan.json", MAX_BYTES)?)?;
    plan.verify()?;
    let definition: definition::DefinitionBinding =
        canonical(&read("definition.json", MAX_BYTES)?)?;
    definition.verify_manifest(&plan.manifest)?;
    require(
        plan.manifest.finality == original
            && plan.operation_id == inventory.operation_id
            && plan.intent_sha256 == inventory.intent_sha256,
        "authority plan or original trust differs",
    )?;
    let completion_bytes = read(&inventory.completion_file, MAX_BYTES)?;
    let completion =
        finality::OriginalCompletion::decode(&inventory.completion_file, &completion_bytes)?;
    let expected_effective = completion
        .effective_trust_file
        .as_deref()
        .unwrap_or("trust-original.json");
    require(
        inventory.effective_trust_file == expected_effective,
        "authority effective trust locator differs",
    )?;
    let effective = if expected_effective == "trust-original.json" {
        original.clone()
    } else {
        canonical::<DeploymentTrustV1>(&read(expected_effective, MAX_BYTES)?)?
    };
    let mut expected = original.clone();
    for peer in &mut expected.peers {
        peer.build_fingerprint = fingerprint;
    }
    require(
        effective == expected,
        "effective peer trust differs from selected target source",
    )?;
    let (runtime, retained_tips) = if let Some(receipt) = &completion.runtime_update {
        let names = runtime_update::portable_record_names(receipt)?;
        let mut records = BTreeMap::new();
        for name in names {
            records.insert(
                name.clone(),
                read(&format!("runtime-update-{name}"), MAX_BYTES)?,
            );
        }
        let projection = runtime_update::verify_public_originals(
            receipt,
            &records,
            &original,
            &effective,
            plan.manifest.network_id,
            target_commit,
            target_version,
        )?;
        (
            Some(projection),
            runtime_update::retained_tip_claims(receipt, &records)?,
        )
    } else {
        (None, runtime_update::RetainedTips::default())
    };
    let mut prepared = Vec::new();
    let mut budget = DeploymentBudget::new(&plan.manifest)?;
    for phase in PHASES {
        let retained: PreparedV1 = canonical(&read(&format!("{phase}.prepared.json"), MAX_BYTES)?)?;
        let transaction = retained.verify(&plan, phase)?;
        let claim: String = canonical(&read(&format!("{phase}.submitted.json"), MAX_BYTES)?)?;
        require(
            claim == digest(&json::to_vec(&retained)?),
            "allocation dispatch original changed its signed phase",
        )?;
        budget.reserve(
            phase,
            &retained.transaction_hash,
            fee_liability(&plan.manifest, &retained.fee_quote)?,
        )?;
        prepared.push((retained, transaction));
    }
    let (phases, peers) =
        completion.replay(&plan, &effective, &prepared, &retained_tips, &mut read)?;
    drop(read);
    require(
        consumed.len() == inventory.files.len(),
        "authority inventory contains unrelated or unconsumed originals",
    )?;
    let namespace = plan.bootstrap_grant.dataspace.canonical_name.to_string();
    let dataspace = plan.manifest.dataspace.descriptor.id.as_u64();
    let lane = plan.manifest.lane.id.as_u32();
    let genesis_wire = hex::decode(&original.genesis_signed_wire_hex)?;
    let (genesis_hash, _) = iroha_core::release_identity::genesis_identity(
        &genesis_wire,
        &original.genesis_public_key,
    )?;
    let visibility = match plan.manifest.lane.visibility {
        iroha_data_model::nexus::LaneVisibility::Public => "public",
        iroha_data_model::nexus::LaneVisibility::Restricted => "restricted",
    };
    let projection = norito::json!({"schema":"iroha.dataspace-authority-verification.v1",
        "scope":{"completed_allocation_verified":true,"source_signature_verified":false,"portable_host_custody_verified":false,"live_readiness_verified":false,"asset_deployment_verified":false},
        "authority_sha256":(digest(authority_bytes)),"trust_profile_sha256":(digest(independent_trust)),"completion_sha256":(digest(&completion_bytes)),
        "operation_id":(plan.operation_id.clone()),"intent_sha256":(plan.intent_sha256.clone()),"source_commit":target_commit,"source_version":target_version,
        "effective_trust_sha256":(digest(&json::to_vec(&effective)?)),"network_id":(plan.manifest.network_id.to_string()),"chain_id":(original.chain.to_string()),
        "account_chain_discriminant":(original.account_chain_discriminant.to_string()),"signed_genesis_sha256":(digest(&genesis_wire)),
        "genesis_block_hash":(genesis_hash.to_string()),"genesis_public_key":(original.genesis_public_key.to_string()),"owner":(plan.manifest.owner.to_string()),
        "dataspace":{"id":(dataspace.to_string()),"lane_id":(lane.to_string()),"name":(plan.manifest.dataspace.descriptor.alias.clone()),"namespace":(namespace.clone()),"visibility":visibility,"lane_manifest_sha256":(digest(&json::to_vec(&plan.manifest.lane_manifest)?))},
        "phases":phases,"peers":peers,"runtime_update":runtime});
    Ok(VerifiedDataspaceAuthority {
        network: plan.manifest.network_id,
        owner: plan.manifest.owner,
        dataspace,
        lane,
        namespace,
        source_commit: target_commit.into(),
        source_version: target_version.into(),
        operation_id: plan.operation_id,
        intent_sha256: plan.intent_sha256,
        authority_sha256: digest(authority_bytes),
        trust_profile_sha256: digest(independent_trust),
        completion_sha256: digest(&completion_bytes),
        projection,
    })
}

fn closure_names(inventory: &Inventory) -> BTreeSet<String> {
    inventory
        .files
        .iter()
        .map(|r| r.path.clone())
        .chain(["authority.json".into(), "lock".into()])
        .collect()
}
#[cfg(unix)]
fn revalidate_directory(journal: &Journal, inventory: &Inventory) -> Result<()> {
    journal.revalidate()?;
    let names = fs::read_dir(&journal.path)?
        .map(|row| {
            row?.file_name()
                .into_string()
                .map_err(|_| eyre!("authority filename is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    require(
        names == closure_names(inventory) && journal._lock.metadata()?.len() == 0,
        "authority directory contains missing or unrelated files",
    )?;
    for row in &inventory.files {
        let bytes = journal
            .read_optional_bounded(&row.path, bound(&row.path))?
            .ok_or_else(|| eyre!("authority original disappeared"))?;
        require(
            bytes.len() as u64 == decimal(&row.size_bytes)? && digest(&bytes) == row.sha256,
            "authority original changed during replay",
        )?;
    }
    journal.revalidate()
}

impl VerifyAuthority {
    #[cfg(unix)]
    pub(crate) fn run_without_client_config(&self, mut output: impl std::io::Write) -> Result<()> {
        let trust = PublicInput::read(&self.trust)?;
        let journal = Journal::open(&self.bundle, false)?;
        let bytes = journal
            .read_optional("authority.json")?
            .ok_or_else(|| eyre!("authority inventory is missing"))?;
        let inventory = Inventory::decode(&bytes)?;
        revalidate_directory(&journal, &inventory)?;
        let verified = verify(
            &bytes,
            &inventory,
            &trust.bytes,
            &self.source_commit,
            &self.source_version,
            |name, maximum| {
                journal
                    .read_optional_bounded(name, maximum)?
                    .ok_or_else(|| eyre!("authority original missing"))
            },
        )?;
        revalidate_directory(&journal, &inventory)?;
        require(
            journal.read_optional("authority.json")?.as_deref() == Some(bytes.as_slice()),
            "authority inventory changed",
        )?;
        trust.revalidate()?;
        let projection = verified.projection_bytes()?;
        profile::publish_profile(&self.output, &projection)?;
        // The held source closure remains authoritative until the result is returned.
        revalidate_directory(&journal, &inventory)?;
        trust.revalidate()?;
        output.write_all(&projection)?;
        output.write_all(b"\n")?;
        Ok(())
    }
    #[cfg(not(unix))]
    pub(crate) fn run_without_client_config(&self, _: impl std::io::Write) -> Result<()> {
        eyre::bail!("authority file custody requires Unix")
    }
}

pub(super) fn export(
    journal: &Journal,
    plan: &PlanV1,
    report: &ReportV1,
    trust_path: &Path,
    update: Option<&runtime_update::Verified>,
    destination: &Path,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (journal, plan, report, trust_path, update, destination);
        eyre::bail!("authority export requires Unix");
    }
    #[cfg(unix)]
    {
        require(
            report.deployment_complete
                && report.state == "completed"
                && report.verification_error.is_none(),
            "authority export requires this invocation's completed allocation verification",
        )?;
        let completion_file = report
            .completion_receipt
            .as_ref()
            .ok_or_else(|| eyre!("no completed allocation receipt"))?;
        let completion_bytes = journal
            .read_optional(completion_file)?
            .ok_or_else(|| eyre!("completed receipt disappeared"))?;
        let completion = finality::OriginalCompletion::decode(completion_file, &completion_bytes)?;
        let original_trust = PublicInput::read(trust_path)?;
        let original: DeploymentTrustV1 = json::from_slice(&original_trust.bytes)?;
        require(
            original == plan.manifest.finality,
            "export trust changed from verified plan",
        )?;
        let (target_commit, target_version) = if let Some(update) = update {
            (update.source_commit.clone(), update.source_version.clone())
        } else {
            let identity = crate::compiled_build_identity()?;
            (
                identity.release_source_commit()?.to_owned(),
                identity.version().to_owned(),
            )
        };
        let mut names = completion.files()?;
        names.extend(FIXED.into_iter().map(str::to_owned));
        names.insert(completion_file.clone());
        if let Some(file) = &completion.effective_trust_file {
            names.insert(file.clone());
        }
        let public_runtime = if let Some(update) = update {
            require(
                completion.runtime_update.as_ref() == Some(&update.receipt),
                "completed runtime update changed",
            )?;
            update.public_originals()?
        } else {
            require(
                completion.runtime_update.is_none(),
                "completion runtime admission is absent",
            )?;
            BTreeMap::new()
        };
        names.extend(
            public_runtime
                .keys()
                .map(|name| format!("runtime-update-{name}")),
        );
        require(
            names.len() <= MAX_FILES,
            "authority closure exceeds file bound",
        )?;
        let bundle = Journal::open(destination, true)?;
        let mut files = Vec::new();
        let mut total = 0u64;
        for name in names {
            let bytes = if name == "trust-original.json" {
                original_trust.bytes.clone()
            } else if let Some(original) = name.strip_prefix("runtime-update-") {
                public_runtime[original].clone()
            } else {
                journal
                    .read_optional_bounded(&name, bound(&name))?
                    .ok_or_else(|| eyre!("verified allocation original disappeared"))?
            };
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| eyre!("authority size overflow"))?;
            require(
                total <= MAX_TOTAL,
                "authority closure exceeds total byte bound",
            )?;
            bundle.install_bounded(&name, &bytes, bound(&name))?;
            files.push(FileRow {
                path: name,
                size_bytes: bytes.len().to_string(),
                sha256: digest(&bytes),
            });
        }
        let inventory = Inventory {
            schema: SCHEMA.into(),
            operation_id: plan.operation_id.clone(),
            intent_sha256: plan.intent_sha256.clone(),
            completion_file: completion_file.clone(),
            original_trust_file: "trust-original.json".into(),
            effective_trust_file: completion
                .effective_trust_file
                .clone()
                .unwrap_or_else(|| "trust-original.json".into()),
            source_commit: target_commit.clone(),
            source_version: target_version.clone(),
            files,
        };
        let bytes = json::to_vec(&inventory)?;
        Inventory::decode(&bytes)?;
        verify(
            &bytes,
            &inventory,
            &original_trust.bytes,
            &target_commit,
            &target_version,
            |name, maximum| {
                bundle
                    .read_optional_bounded(name, maximum)?
                    .ok_or_else(|| eyre!("new authority original disappeared"))
            },
        )?;
        if let Some(update) = update {
            update.revalidate()?;
        }
        journal.revalidate()?;
        original_trust.revalidate()?;
        bundle.install("authority.json", &bytes)?;
        revalidate_directory(&bundle, &inventory)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn inventory() -> Inventory {
        Inventory {
            schema: SCHEMA.into(),
            operation_id: "operation".into(),
            intent_sha256: "a".repeat(64),
            completion_file: format!("completion-{}.json", "b".repeat(64)),
            original_trust_file: "trust-original.json".into(),
            effective_trust_file: "trust-original.json".into(),
            source_commit: "c".repeat(40),
            source_version: "2.0.0".into(),
            files: vec![FileRow {
                path: "plan.json".into(),
                size_bytes: "2".into(),
                sha256: digest(b"{}"),
            }],
        }
    }

    #[test]
    fn authority_inventory_refuses_unknown_duplicate_traversal_and_rounded_size() {
        let valid = json::to_vec(&inventory()).unwrap();
        Inventory::decode(&valid).unwrap();
        let rows = dataspace_authority_original_inventory(&valid).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path(), "plan.json");
        assert_eq!(rows[0].size_bytes(), 2);
        assert_eq!(rows[0].sha256(), digest(b"{}"));
        for mutate in 0..9 {
            let mut input: json::Value = json::from_slice(&valid).unwrap();
            match mutate {
                0 => {
                    input
                        .as_object_mut()
                        .unwrap()
                        .insert("extra".into(), norito::json!(true));
                }
                1 => {
                    *input.get_mut("schema").unwrap() = norito::json!("old-allocation");
                }
                2 => {
                    *input
                        .get_mut("files")
                        .unwrap()
                        .get_mut(0usize)
                        .unwrap()
                        .get_mut("path")
                        .unwrap() = norito::json!("../plan.json");
                }
                3 => {
                    *input
                        .get_mut("files")
                        .unwrap()
                        .get_mut(0usize)
                        .unwrap()
                        .get_mut("size_bytes")
                        .unwrap() = norito::json!(2);
                }
                4 => {
                    *input
                        .get_mut("files")
                        .unwrap()
                        .get_mut(0usize)
                        .unwrap()
                        .get_mut("size_bytes")
                        .unwrap() = norito::json!("02");
                }
                5 => {
                    let row = input["files"][0usize].clone();
                    input
                        .get_mut("files")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()
                        .push(row);
                }
                6 => {
                    *input
                        .get_mut("files")
                        .unwrap()
                        .get_mut(0usize)
                        .unwrap()
                        .get_mut("sha256")
                        .unwrap() = norito::json!("A".repeat(64));
                }
                7 => {
                    *input
                        .get_mut("files")
                        .unwrap()
                        .get_mut(0usize)
                        .unwrap()
                        .get_mut("path")
                        .unwrap() = norito::json!("lock");
                }
                _ => {
                    *input
                        .get_mut("files")
                        .unwrap()
                        .get_mut(0usize)
                        .unwrap()
                        .get_mut("size_bytes")
                        .unwrap() = norito::json!("18446744073709551616");
                }
            }
            // Decode to the typed canonical ordering where possible; unknown fields
            // must still be rejected by the original-byte entry itself.
            let bytes = json::from_value::<Inventory>(input.clone())
                .ok()
                .and_then(|v| json::to_vec(&v).ok())
                .unwrap_or_else(|| json::to_vec(&input).unwrap());
            assert!(Inventory::decode(&bytes).is_err(), "mutation {mutate}");
            assert!(
                dataspace_authority_original_inventory(&bytes).is_err(),
                "public mutation {mutate}"
            );
        }
        assert_eq!(
            decimal("8648377547929788715").unwrap(),
            8_648_377_547_929_788_715
        );
        for bad in [
            "8648377547929789000.0",
            "8.648377547929789e18",
            "-1",
            "+1",
            " 1",
            "00",
        ] {
            assert!(decimal(bad).is_err());
        }
    }

    #[test]
    fn authority_shared_entry_refuses_missing_extra_and_unsigned_success_originals() {
        let bytes = json::to_vec(&inventory()).unwrap();
        let empty = BTreeMap::new();
        assert!(
            verify_dataspace_authority_originals(&bytes, &empty, b"{}", &"c".repeat(40), "2.0.0")
                .is_err()
        );
        let fabricated = BTreeMap::from([
            ("plan.json".into(), b"{}".to_vec()),
            (
                "success.json".into(),
                br#"{"deployment_complete":true}"#.to_vec(),
            ),
        ]);
        assert!(
            verify_dataspace_authority_originals(
                &bytes,
                &fabricated,
                b"{}",
                &"c".repeat(40),
                "2.0.0"
            )
            .is_err()
        );
        let exact = BTreeMap::from([("plan.json".into(), b"{}".to_vec())]);
        assert!(
            verify_dataspace_authority_originals(&bytes, &exact, b"{}", &"d".repeat(40), "2.0.0")
                .unwrap_err()
                .to_string()
                .contains("target source")
        );
    }

    #[test]
    fn authority_custody_rejects_extra_symlink_hardlink_and_changed_originals() {
        let root = super::super::tests::private_tempdir();
        let bundle = Journal::open(&root.path().join("bundle"), true).unwrap();
        let inventory = inventory();
        bundle.install("plan.json", b"{}").unwrap();
        bundle
            .install("authority.json", &json::to_vec(&inventory).unwrap())
            .unwrap();
        revalidate_directory(&bundle, &inventory).unwrap();
        bundle.install("unrelated.json", b"{}").unwrap();
        assert!(revalidate_directory(&bundle, &inventory).is_err());
        fs::remove_file(bundle.path.join("unrelated.json")).unwrap();
        let original = bundle.path.join("plan.json");
        let retained = root.path().join("retained.json");
        fs::rename(&original, &retained).unwrap();
        symlink(&retained, &original).unwrap();
        assert!(revalidate_directory(&bundle, &inventory).is_err());
        fs::remove_file(&original).unwrap();
        fs::hard_link(&retained, &original).unwrap();
        assert!(revalidate_directory(&bundle, &inventory).is_err());
        fs::remove_file(&original).unwrap();
        fs::rename(&retained, &original).unwrap();
        fs::write(&original, b"[]").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(revalidate_directory(&bundle, &inventory).is_err());
    }

    #[test]
    fn authority_local_cli_accepts_independent_target_and_rejects_credentials() {
        use clap::Parser as _;
        let args = crate::Args::try_parse_from([
            "iroha",
            "dataspace",
            "verify-authority",
            "--bundle",
            "/bundle",
            "--trust",
            "/trust",
            "--source-commit",
            &"c".repeat(40),
            "--source-version",
            "2.0.0",
            "--output",
            "/result",
        ])
        .unwrap();
        assert!(crate::run_local_dataspace_profile(&args, Vec::new()).is_some());
        let args = crate::Args::try_parse_from([
            "iroha",
            "--config",
            "/private-client",
            "dataspace",
            "verify-authority",
            "--bundle",
            "/bundle",
            "--trust",
            "/trust",
            "--source-commit",
            &"c".repeat(40),
            "--source-version",
            "2.0.0",
            "--output",
            "/result",
        ])
        .unwrap();
        assert!(
            crate::run_local_dataspace_profile(&args, Vec::new())
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("credential-free")
        );
    }

    #[test]
    fn authority_status_export_is_unavailable_to_plan_or_apply() {
        use clap::Parser as _;
        for action in ["plan", "apply", "status"] {
            let args = crate::Args::try_parse_from([
                "iroha",
                "dataspace",
                action,
                "/definition",
                "--trust",
                "/trust",
                "--export-authority",
                "/new-bundle",
            ])
            .unwrap();
            let crate::Command::Dataspace(command) = args.command else {
                panic!("wrong command");
            };
            assert_eq!(
                command
                    .verification_origins(&finality::test_trust())
                    .is_ok(),
                action == "status"
            );
        }
    }
    #[test]
    fn authority_separate_target_is_read_only_paired_and_requires_actual_runtime_update() {
        use clap::Parser as _;
        let source = "c".repeat(40);
        let tail = [
            "--verification-runtime-update",
            "/private/runtime/taira-public-reset/update-00000000000000000000000000000000",
            "--verification-source-commit",
            source.as_str(),
            "--verification-source-version",
            "2.0.0-rc.2.0",
        ];
        for action in ["plan", "apply", "status"] {
            let args = crate::Args::try_parse_from(
                [
                    "iroha",
                    "dataspace",
                    action,
                    "/definition",
                    "--trust",
                    "/trust",
                ]
                .into_iter()
                .chain(tail),
            )
            .unwrap();
            let crate::Command::Dataspace(command) = args.command else {
                panic!("wrong command")
            };
            assert_eq!(
                command
                    .verification_origins(&finality::test_trust())
                    .is_ok(),
                action == "status"
            );
        }
        for missing in [0, 2, 4] {
            let args = [
                "iroha",
                "dataspace",
                "status",
                "/definition",
                "--trust",
                "/trust",
            ]
            .into_iter()
            .chain(
                tail.into_iter()
                    .enumerate()
                    .filter_map(|(i, item)| (!(missing..missing + 2).contains(&i)).then_some(item)),
            );
            assert!(
                crate::Args::try_parse_from(args).is_err(),
                "missing pair at {missing}"
            );
        }
        // Target selection is source-derived; neither a caller fingerprint nor an
        // invalid version/commit can authorize a live host observation.
        for (commit, version) in [
            ("short", "2.0.0"),
            (source.as_str(), ""),
            (source.as_str(), "2.0.0\n"),
        ] {
            assert!(runtime_update::selected_source_fingerprint(commit, version).is_err());
        }
    }

    #[test]
    fn authority_runtime_chain_cli_preserves_order_and_refuses_mutating_or_unbounded_selection() {
        use clap::Parser as _;
        let paths = (0..17)
            .map(|index| format!("/private/runtime/taira-public-reset/update-{index:032x}"))
            .collect::<Vec<_>>();
        for (action, count, duplicate, accepted) in [
            ("status", 2, false, true),
            ("status", 16, false, true),
            ("status", 17, false, false),
            ("status", 2, true, false),
            ("plan", 2, false, false),
            ("apply", 2, false, false),
        ] {
            let mut words = vec![
                "iroha",
                "dataspace",
                action,
                "/definition",
                "--trust",
                "/trust",
            ];
            for index in 0..count {
                words.extend([
                    "--verification-runtime-update",
                    paths[if duplicate { 0 } else { index }].as_str(),
                ]);
            }
            let args = crate::Args::try_parse_from(words).unwrap();
            let crate::Command::Dataspace(command) = args.command else {
                panic!("wrong command")
            };
            assert_eq!(
                command
                    .verification_origins(&finality::test_trust())
                    .is_ok(),
                accepted
            );
            if let Command::Status(args) = command {
                assert_eq!(args.verification_runtime_update.len(), count);
                if !duplicate {
                    assert_eq!(
                        args.verification_runtime_update[1],
                        PathBuf::from(&paths[1])
                    );
                }
            }
        }
    }
    #[test]
    fn authority_completion_inspection_requires_exact_named_original() {
        let mut inventory = inventory();
        let expected = digest(b"completion original");
        inventory.files.insert(
            0,
            FileRow {
                path: inventory.completion_file.clone(),
                size_bytes: "19".into(),
                sha256: expected.clone(),
            },
        );
        let valid = json::to_vec(&inventory).unwrap();
        assert_eq!(
            dataspace_authority_completion_sha256(&valid).unwrap(),
            expected
        );
        for missing in [
            "completion-wrong.json".to_owned(),
            format!("completion-{}.json", "0".repeat(64)),
            format!("completion-{}.json", "c".repeat(64)),
        ] {
            inventory.completion_file = missing;
            assert!(
                dataspace_authority_completion_sha256(&json::to_vec(&inventory).unwrap()).is_err()
            );
        }
    }
}
