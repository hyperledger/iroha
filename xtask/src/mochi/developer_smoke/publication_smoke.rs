//! Installed publication, real three-provider registry evidence, and an untouched cold consumer.
//!
//! Only the CLI performs writes. SDK reads below observe the normal finalized registry routes;
//! they do not manufacture independent finality or replace any native publication admission.

use super::{CommandDocument, Harness, require_deployment, require_same_context};
use iroha::{
    blocking::AccountClient,
    client::{Client, musubi::QueryResult},
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    musubi::{
        ArchiveId, MusubiArchiveLocationQueryV1, MusubiArchiveLocationStateV1,
        MusubiExactReleaseQueryV1, MusubiPackageIdV1, MusubiPageRequestV1,
        MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRefV1,
        MusubiRegistrySnapshotV1, MusubiReleaseIdV1, MusubiStorageAvailabilityV1,
        musubi_provider_bundle_attestation_set_digest_v1,
    },
    sorafs::capacity::ProviderId,
};
use iroha_deploy::managed::{ManagedStore, PreparedLocalnet};
use norito::json::Value;
use std::{
    error::Error,
    fs,
    io::Read as _,
    path::Path,
    thread,
    time::{Duration, Instant},
};

const PUBLICATION_BUDGET: Duration = Duration::from_secs(600);
const MAX_RESUMES: usize = 16;
const LIBRARY_NAME: &str = "installed-library";
const LIBRARY_SOURCE: &str = "module InstalledLibrary { export fn value() -> int { return 37; } }";
const CONSUMER_SOURCE: &str = "seiyaku InstalledConsumer { view fn quote(int cups) authorize(anyone) -> int { return published::value(); } }";
const PROGRESS_MESSAGE: &str = "publication did not reach exact finalized release verification";

pub(super) fn run(harness: &mut Harness) -> Result<(), Box<dyn Error>> {
    let initial = harness.command(&["localnet", "status"])?;
    super::require_phase(&initial, "ready", 4)?;
    let store = ManagedStore::open(&harness.state)?;
    let context = store.context(None)?;
    let prepared = store.prepared(&context.name)?;
    let original = prepared
        .publication_client_config()?
        .ok_or("no original publication profile")?;
    let plans = prepared
        .provider_service_plans()?
        .ok_or("no original provider plans")?;
    let mut providers = plans.map(|plan| plan.provider_id());
    providers.sort();
    if providers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("original provider inventory is not three distinct providers".into());
    }
    require_original_budgets(&prepared)?;
    let cache = prepared.build_cache_root();
    require_absent(&cache)?;
    if cache == original.publication_cache_root() {
        return Err("publication and cold consumer caches must be separate original roots".into());
    }
    let namespace = original.publication_namespace().to_string();
    let binding = original.namespace_binding();
    let release = MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            binding.home_dataspace,
            binding.scope.clone(),
            LIBRARY_NAME.parse()?,
        ),
        "1.0.0".parse()?,
    );
    let display_release = format!("{namespace}/{LIBRARY_NAME}@1.0.0");
    let publisher = harness.workspace.join("publication-library");
    fs::create_dir(&publisher)?;
    fs::create_dir(publisher.join("src"))?;
    fs::write(publisher.join("Musubi.toml"), library_manifest(&namespace))?;
    fs::write(publisher.join("src/value.ko"), LIBRARY_SOURCE)?;
    // No manual policy, registration, completion, storage injection or source cache is installed.
    let deadline = Instant::now() + PUBLICATION_BUDGET;
    let detached = harness
        .command_document(
            &["package", "publish", "publication-library", "--detach"],
            deadline,
            true,
        )
        .map_err(controller_error)?;
    let mut progress = Progress::from_detached(&detached, &display_release, &release)?;
    let mut completed = None;
    for _ in 0..MAX_RESUMES {
        if Instant::now() >= deadline {
            break;
        }
        let document = harness
            .command_document(
                &["package", "publish", "--resume", &progress.operation],
                deadline,
                true,
            )
            .map_err(controller_error)?;
        if let Some(data) = progress.observe(&document)? {
            completed = Some(data.clone());
            break;
        }
    }
    let completed = completed
        .ok_or("publication did not complete within its original bounded controller turn")?;
    let evidence = Completion::parse(&completed, &context.network_id)?;
    require_registry_on_all_peers(&prepared, &release, &providers, &evidence, deadline)?;

    // Only this test-owned source tree is removed. The original generated operation/CAR,
    // namespace, service and wallet custody remain untouched and are still required on resume.
    fs::remove_dir_all(&publisher)?;
    let replay = harness
        .command_document(
            &["package", "publish", "--resume", &progress.operation],
            deadline,
            true,
        )
        .map_err(controller_error)?;
    let repeated = progress
        .observe(&replay)?
        .ok_or("completed publication became pending")?;
    if repeated != &completed {
        return Err("resume changed the retained complete publication result".into());
    }
    require_absent(&cache)?;
    if store.prepared(&context.name)? != prepared {
        return Err("publication changed original generation".into());
    }
    drop(store);

    let consumer = harness.workspace.join("cold-consumer");
    fs::create_dir(&consumer)?;
    fs::write(consumer.join("Musubi.toml"), consumer_manifest(&namespace))?;
    fs::write(consumer.join("contract.ko"), CONSUMER_SOURCE)?;
    require_absent(&consumer.join("Musubi.lock"))?;
    let deployed = harness.command(&["contract", "deploy", "cold-consumer"])?;
    require_deployment(&deployed)?;
    require_consumer_lock(
        &consumer.join("Musubi.lock"),
        &context.network_id,
        &evidence,
    )?;
    if !cache.is_dir() || fs::read_dir(&cache)?.next().transpose()?.is_none() {
        return Err("cold dependency did not install into the original managed cache".into());
    }
    harness.execute_on_every_peer(&deployed, "37")?;
    let after = harness.command(&["localnet", "status"])?;
    super::require_phase(&after, "ready", 4)?;
    require_same_context(&initial, &after)?;
    eprintln!(
        "[developer-smoke] complete publication, exact three native providers, cold dependent execution on four validators"
    );
    Ok(())
}

fn controller_error(error: super::super::latency::Outcome) -> Box<dyn Error> {
    format!("publication CLI observation failed: {}", error.as_str()).into()
}
fn require_absent(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(format!("cold fixture path was already present: {}", path.display()).into()),
    }
}
fn require_original_budgets(prepared: &PreparedLocalnet) -> Result<(), Box<dyn Error>> {
    use iroha_config::node_config::{NodeConfigOptions, NodeFile, open_node_config};
    if prepared.peers.len() != 4 {
        return Err("publication smoke requires exactly four validators".into());
    }
    for peer in &prepared.peers {
        let reader = open_node_config(
            NodeFile::Path(peer.config_path.clone()),
            NodeConfigOptions::default(),
        )
        .map_err(|_| "original generated validator config could not be opened")?;
        let (user, _) = reader
            .read()
            .map_err(|_| "original generated validator config could not be read")?;
        let actual = user
            .parse()
            .map_err(|_| "original generated validator config could not be parsed")?;
        if actual.pipeline.ivm_execution_max_bytes != 1024 * 1024 * 1024 {
            return Err(
                "installed publication must retain the original one-GiB native execution budget"
                    .into(),
            );
        }
    }
    Ok(())
}
fn library_manifest(namespace: &str) -> String {
    format!(
        "manifest-version = 1\n[package]\nnamespace = {namespace:?}\nname = {LIBRARY_NAME:?}\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nsource-dir = \"src\"\nexports = [\"value\"]\n"
    )
}
fn consumer_manifest(namespace: &str) -> String {
    format!(
        "manifest-version = 1\n[package]\nnamespace = \"consumer\"\nname = \"installed-consumer\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[dependencies]\npublished = {{ package = \"{namespace}/{LIBRARY_NAME}\", version = \"=1.0.0\" }}\n[[contract]]\nname = \"installed-consumer\"\npath = \"contract.ko\"\n"
    )
}

// This closed parser accepts presentation progress only. It creates no native receipt, signature,
// snapshot or finality capability; the actual runtime and SDK perform those checks independently.
struct Progress {
    operation: String,
    release: String,
    structural_release: String,
    phase: u8,
}
impl Progress {
    fn from_detached(
        document: &CommandDocument,
        display: &str,
        release: &MusubiReleaseIdV1,
    ) -> Result<Self, Box<dyn Error>> {
        let data = success_data(document)?;
        if text(data, "status")? != "detached"
            || text(data, "phase")? != "seed-ingress"
            || text(data, "release")? != display
            || text(data, "structural_release")? != release.to_string()
        {
            return Err(
                "initial publication did not retain the exact detached seed-ingress operation"
                    .into(),
            );
        }
        let operation = text(data, "operation_id")?.to_owned();
        digest(&operation)?;
        Ok(Self {
            operation,
            release: display.to_owned(),
            structural_release: release.to_string(),
            phase: 1,
        })
    }
    fn observe<'a>(
        &mut self,
        document: &'a CommandDocument,
    ) -> Result<Option<&'a Value>, Box<dyn Error>> {
        envelope(&document.value)?;
        if document.exit_code == Some(0) {
            let data = success_data(document)?;
            if text(data, "status")? != "complete"
                || text(data, "operation_id")? != self.operation
                || text(data, "release")? != self.release
                || text(data, "structural_release")? != self.structural_release
            {
                return Err("publication completion changed its exact original selection".into());
            }
            return Ok(Some(data));
        }
        let error = field(&document.value, "error")?;
        let context = field(error, "context")?;
        if document.exit_code != Some(9)
            || document.value.get("ok").and_then(Value::as_bool) != Some(false)
            || text(error, "code")? != "MUSUBI_E_PUBLISH"
            || text(error, "message")? != PROGRESS_MESSAGE
            || text(context, "operation_id")? != self.operation
        {
            return Err(
                "publication failed outside the exact original pending/progress response".into(),
            );
        }
        let phase = match text(context, "phase")? {
            "SeedIngress" => 1,
            "ArchiveRegistration" => 2,
            "Replication" => 3,
            "Readback" => 4,
            "ReleaseSubmission" => 5,
            "FinalVerification" => 6,
            _ => return Err("publication returned an unknown or retired progress phase".into()),
        };
        if phase < self.phase {
            return Err("publication phase regressed".into());
        }
        self.phase = phase;
        Ok(None)
    }
}
fn envelope(value: &Value) -> Result<(), Box<dyn Error>> {
    if text(value, "schema")? != "musubi-cli-output"
        || value.get("version").and_then(Value::as_u64) != Some(1)
        || text(value, "command")? != "publish"
    {
        return Err("wrong publication output envelope".into());
    }
    Ok(())
}
fn success_data(document: &CommandDocument) -> Result<&Value, Box<dyn Error>> {
    envelope(&document.value)?;
    if document.exit_code != Some(0)
        || document.value.get("ok").and_then(Value::as_bool) != Some(true)
    {
        return Err("publication CLI did not report success".into());
    }
    field(&document.value, "data")
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(key)
        .ok_or_else(|| format!("publication output omits {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| format!("publication output {key} is not text").into())
}
fn positive(value: &Value, key: &str) -> Result<u64, Box<dyn Error>> {
    field(value, key)?
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("publication output {key} is not positive").into())
}
fn digest(raw: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("publication identity is not canonical lowercase hexadecimal".into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(raw, &mut bytes)?;
    if bytes == [0; 32] {
        return Err("publication identity is zero".into());
    }
    Ok(bytes)
}
struct Completion {
    archive: ArchiveId,
    release_digest: [u8; 32],
    height: u64,
    block: [u8; 32],
    revision: u64,
    applied_height: u64,
}
impl Completion {
    fn parse(data: &Value, network: &str) -> Result<Self, Box<dyn Error>> {
        if text(data, "network_id")? != network {
            return Err("publication network differs".into());
        }
        for key in [
            "home_release_digest",
            "universal_release_digest",
            "checkpoint_digest",
        ] {
            digest(text(data, key)?)?;
        }
        let snapshot = field(data, "snapshot")?;
        let submission = field(data, "amx_submission")?;
        digest(text(submission, "instruction_digest")?)?;
        digest(text(submission, "transaction_hash")?)?;
        let result = Self {
            archive: ArchiveId::new(digest(text(data, "archive_id")?)?),
            release_digest: digest(text(data, "release_digest")?)?,
            height: positive(snapshot, "finalized_height")?,
            block: digest(text(snapshot, "finalized_block_hash")?)?,
            revision: positive(snapshot, "index_revision")?,
            applied_height: positive(submission, "applied_height")?,
        };
        if result.applied_height <= 1 || result.height < result.applied_height {
            return Err(
                "publication completion does not follow its real applied transaction".into(),
            );
        }
        Ok(result)
    }
    fn covers(&self, snapshot: &MusubiRegistrySnapshotV1) -> bool {
        snapshot.finalized_height >= self.height
            && snapshot.index_revision >= self.revision
            && (snapshot.finalized_height != self.height
                || snapshot.finalized_block_hash == self.block)
    }
}

fn require_registry_on_all_peers(
    prepared: &PreparedLocalnet,
    release: &MusubiReleaseIdV1,
    providers: &[ProviderId; 3],
    complete: &Completion,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let config = prepared.context.load_client_config()?;
    let _chain = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    for (index, peer) in prepared.peers.iter().enumerate() {
        let mut selected = config.clone();
        selected.torii_api_url = peer.torii_url.parse()?;
        let peer_deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        let client = Client::builder(selected)
            .build()?
            .with_request_deadline(peer_deadline);
        let account = AccountClient::from_client(client.account_client()?)?;
        loop {
            if Instant::now() >= peer_deadline {
                return Err(format!(
                    "peer {index} did not observe the exact publication before deadline"
                )
                .into());
            }
            if registry_observed(&account, &config, release, providers, complete)? {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}
fn registry_observed(
    account: &AccountClient,
    config: &iroha::config::Config,
    release: &MusubiReleaseIdV1,
    providers: &[ProviderId; 3],
    complete: &Completion,
) -> Result<bool, Box<dyn Error>> {
    let registry = account.musubi();
    let exact = match registry.exact_release(&MusubiExactReleaseQueryV1 {
        release: release.clone(),
    })? {
        QueryResult::Found(value) => value,
        QueryResult::NotFound => return Ok(false),
        QueryResult::StaleCursor => return Err("exact release returned a cursor refusal".into()),
    };
    if !complete.covers(&exact.snapshot) {
        return Ok(false);
    }
    let storage = &exact.universal_release.selection.storage;
    if exact.network_id != config.network_id
        || exact.home_release.manifest.archive_id != complete.archive
        || exact.home_release.release_digest.as_bytes() != &complete.release_digest
        || exact.home_release.published_by != config.account
        || exact.home_release.published_at_height != complete.applied_height
        || storage.availability != MusubiStorageAvailabilityV1::Selectable
        || storage.healthy_replicas != 3
    {
        return Err(
            "native finalized release does not bind the complete three-provider publication".into(),
        );
    }
    let locations = match registry.archive_locations(&MusubiArchiveLocationQueryV1 {
        archive_id: complete.archive,
        page: MusubiPageRequestV1 {
            limit: 16,
            cursor: None,
        },
    })? {
        QueryResult::Found(value) => value,
        QueryResult::NotFound => return Ok(false),
        QueryResult::StaleCursor => {
            return Err("archive locations returned a cursor refusal".into());
        }
    };
    if !complete.covers(&locations.snapshot) {
        return Ok(false);
    }
    if locations.network_id != config.network_id
        || locations.archive.registered_by != config.account
        || locations.next_cursor.is_some()
        || locations.items.len() != 1
    {
        return Err("fresh smoke archive has an unexpected native location inventory".into());
    }
    let location = &locations.items[0];
    if location.providers.as_slice() != providers
        || location.state != MusubiArchiveLocationStateV1::Healthy
    {
        return Err(
            "native location does not contain exactly the three original healthy providers".into(),
        );
    }
    let mut references = Vec::with_capacity(3);
    for provider in providers {
        let key = MusubiProviderBundleAttestationKeyV1 {
            archive_id: complete.archive,
            replication_order: location.replication_order,
            provider_id: *provider,
        };
        let record = match registry.provider_bundle_attestation(&key)? {
            QueryResult::Found(value) => value,
            QueryResult::NotFound => return Ok(false),
            QueryResult::StaleCursor => {
                return Err("provider attestation returned a cursor refusal".into());
            }
        };
        // The SDK already runs the canonical full attestation/key/signature validator. The
        // finalized route's native registration remains the owner of current admission checks.
        if record.registered_by != config.account
            || record.attestation.payload.binding.network_id != config.network_id
            || record.registered_at_height > location.finalized_height
        {
            return Err(
                "provider attestation differs from original publication or location history".into(),
            );
        }
        references.push(MusubiProviderBundleAttestationRefV1 {
            provider_id: *provider,
            digest: record.attestation_digest,
        });
    }
    if musubi_provider_bundle_attestation_set_digest_v1(
        complete.archive,
        location.replication_order,
        &references,
    )? != location.provider_attestation_set_digest
    {
        return Err(
            "native location differs from the three actual signed completion attestations".into(),
        );
    }
    Ok(true)
}
fn require_consumer_lock(
    path: &Path,
    network: &str,
    complete: &Completion,
) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(super::MAX_OUTPUT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > super::MAX_OUTPUT {
        return Err("one-dependency smoke lock is oversized".into());
    }
    // Presentation inspection of the actual compiler-owned lock, never an alternate lock verifier.
    let lock: toml::Table = toml::from_str(std::str::from_utf8(&bytes)?)?;
    let nodes = lock
        .get("node")
        .and_then(toml::Value::as_array)
        .ok_or("cold lock has no registry node")?;
    if lock.get("schema").and_then(toml::Value::as_str) != Some("musubi-lock")
        || lock.get("version").and_then(toml::Value::as_integer) != Some(1)
        || lock.get("context").and_then(toml::Value::as_str) != Some("registry")
        || lock.get("network-id").and_then(toml::Value::as_str) != Some(network)
        || nodes.len() != 1
        || nodes[0].get("name").and_then(toml::Value::as_str) != Some(LIBRARY_NAME)
        || nodes[0].get("version").and_then(toml::Value::as_str) != Some("1.0.0")
        || nodes[0].get("archive-id").and_then(toml::Value::as_str)
            != Some(hex::encode(complete.archive.as_bytes()).as_str())
        || nodes[0].get("release-digest").and_then(toml::Value::as_str)
            != Some(hex::encode(complete.release_digest).as_str())
    {
        return Err(
            "cold compiler lock does not select the exact newly published registry archive".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
