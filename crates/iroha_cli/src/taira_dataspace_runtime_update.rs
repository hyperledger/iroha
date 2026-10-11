//! Read-only build-identity transition after an actual preserved-state Taira update.
//! A native retired-table receipt may change config file metadata, never peer config authority.
//! Original deployment intent and genesis/peer/config authority are never rewritten.

use super::*;
use base64::Engine as _;
use iroha_crypto::Hash;

const MAX_UPDATES: usize = 16;
const CHAIN_SCHEMA: &str = "iroha.dataspace-runtime-update-chain-verification.v1";

const BASE: &str = "/private/runtime/taira-public-reset";
const RECORDS: [&str; 7] = [
    "intent.json",
    "result.json",
    "retained-entry.json",
    "after.json",
    "checkpoint-stopped.json",
    "checkpoint-restored.json",
    "cohort-ready.json",
];

/// Compute the existing native build identity from independently selected target source.
/// Source signature/tree verification belongs to the caller's accepted source authority.
pub(super) fn selected_source_fingerprint(source: &str, version: &str) -> Result<Hash> {
    require(
        source.len() == 40
            && source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !version.is_empty()
            && version.len() <= 128
            && version.trim() == version
            && version.bytes().all(|b| b.is_ascii_graphic()),
        "selected target source or version is malformed",
    )?;
    // Identical to release_identity::BuildIdentity::build_fingerprint and the
    // existing prior-build join below; this is not a caller-selected fingerprint.
    Ok(Hash::new([version.as_bytes(), source.as_bytes()].concat()))
}

#[derive(JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct PublicReceipt {
    schema: String,
    operation_directory: String,
    source_commit: String,
    receipt_sha256: BTreeMap<String, String>,
    original_trust_sha256: String,
    effective_trust_sha256: String,
    chain_write_performed: bool,
}

#[derive(JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct ChainReceipt {
    schema: String,
    source_commit: String,
    original_trust_sha256: String,
    effective_trust_sha256: String,
    updates: Vec<json::Value>,
    chain_write_performed: bool,
}

/// Bounded explicit read-only selection; no filesystem or credentials are opened.
pub(super) fn validate_selection(paths: &[PathBuf]) -> Result<()> {
    require(
        paths.len() <= MAX_UPDATES
            && paths.iter().all(|path| operation_name(path).is_ok())
            && paths
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == paths.len(),
        "runtime update selection must be bounded and nonduplicate",
    )
}

fn operation_name(path: &Path) -> Result<&str> {
    let operation = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| eyre!("invalid runtime update path"))?;
    require(
        path.to_str() == Some(format!("{BASE}/{operation}").as_str())
            && operation.strip_prefix("update-").is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
        "runtime update must select one exact retained operation",
    )?;
    Ok(operation)
}

fn chain_receipt(value: &json::Value) -> Result<Option<ChainReceipt>> {
    if value.get("schema").and_then(json::Value::as_str) != Some(CHAIN_SCHEMA) {
        return Ok(None);
    }
    let chain: ChainReceipt = json::from_value(value.clone())?;
    require(
        (2..=MAX_UPDATES).contains(&chain.updates.len()) && !chain.chain_write_performed,
        "runtime update chain must be bounded, nonempty and read-only",
    )?;
    let mut operations = std::collections::BTreeSet::new();
    let mut sources = std::collections::BTreeSet::new();
    for value in &chain.updates {
        single_record_names(value)?;
        let step: PublicReceipt = json::from_value(value.clone())?;
        require(
            operations.insert(step.operation_directory) && sources.insert(step.source_commit),
            "runtime update chain repeats an operation or source",
        )?;
    }
    Ok(Some(chain))
}

fn chain_name(index: usize, name: &str) -> String {
    format!("chain-{index:04}-{name}")
}

/// Exact portable closure for either the original single update or a bounded chain.
pub(super) fn portable_record_names(value: &json::Value) -> Result<Vec<String>> {
    if let Some(chain) = chain_receipt(value)? {
        let mut names = Vec::new();
        for (index, step) in chain.updates.iter().enumerate() {
            names.extend(
                single_record_names(step)?
                    .iter()
                    .map(|name| chain_name(index, name)),
            );
        }
        Ok(names)
    } else {
        single_record_names(value)
    }
}

/// Select only the existing public seven originals plus the exact optional retirement pair.
fn single_record_names(receipt: &json::Value) -> Result<Vec<String>> {
    let receipt: PublicReceipt = json::from_value(receipt.clone())?;
    let mut required = RECORDS
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let prepared = receipt
        .receipt_sha256
        .contains_key("config-retirement-prepared.json");
    let installed = receipt
        .receipt_sha256
        .contains_key("config-retirement-installed.json");
    require(
        prepared == installed,
        "portable runtime config retirement pair is incomplete",
    )?;
    if prepared {
        required.insert("config-retirement-prepared.json".into());
        required.insert("config-retirement-installed.json".into());
    }
    require(
        receipt.schema == "iroha.dataspace-runtime-update-verification.v1"
            && !receipt.chain_write_performed
            && receipt
                .receipt_sha256
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                == required
            && receipt.receipt_sha256.values().all(|v| {
                v.len() == 64
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
        "portable runtime receipt fields or original closure differ",
    )?;
    Ok(required.into_iter().collect())
}

/// Recheck public original hashes and semantic joins without claiming host custody.
fn verify_single_public_originals(
    value: &json::Value,
    originals: &BTreeMap<String, Vec<u8>>,
    original: &DeploymentTrustV1,
    effective: &DeploymentTrustV1,
    network: NetworkId,
    source: &str,
    version: &str,
) -> Result<json::Value> {
    let names = single_record_names(value)?;
    let receipt: PublicReceipt = json::from_value(value.clone())?;
    let directory = Path::new(&receipt.operation_directory);
    let operation = operation_name(directory)?;
    require(
        directory.parent() == Some(Path::new(BASE))
            && operation.strip_prefix("update-").is_some_and(|s| {
                s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            && receipt.source_commit == source
            && receipt.original_trust_sha256 == digest(&json::to_vec(original)?)
            && receipt.effective_trust_sha256 == digest(&json::to_vec(effective)?)
            && originals.len() == names.len(),
        "portable runtime selection or trust join differs",
    )?;
    let fingerprint = selected_source_fingerprint(source, version)?;
    let mut selected = original.clone();
    for peer in &mut selected.peers {
        peer.build_fingerprint = fingerprint;
    }
    require(
        selected == *effective,
        "portable runtime changed non-build trust authority",
    )?;
    let mut records = BTreeMap::new();
    for name in names {
        let bytes = originals
            .get(&name)
            .ok_or_else(|| eyre!("portable runtime original missing"))?;
        require(
            bytes.len() <= MAX_BYTES && digest(bytes) == receipt.receipt_sha256[&name],
            "portable runtime original bytes changed",
        )?;
        records.insert(name, json::from_slice(bytes)?);
    }
    validate_records(&records, operation, network, source, original, version)?;
    Ok(
        norito::json!({"schema":"iroha.dataspace-runtime-update-public-joins.v1", "operation":operation,
        "source_commit":source,"receipt_sha256":(digest(&json::to_vec(value)?)),"record_sha256":(receipt.receipt_sha256),
        "semantic_joins_verified":true,"host_custody_verified":false}),
    )
}

/// Replay every original transition from the unchanged allocation trust. A chain
/// carries historical producer DATA, not a substitute live-custody signature.
pub(super) fn verify_public_originals(
    value: &json::Value,
    originals: &BTreeMap<String, Vec<u8>>,
    original: &DeploymentTrustV1,
    effective: &DeploymentTrustV1,
    network: NetworkId,
    source: &str,
    version: &str,
) -> Result<json::Value> {
    let Some(chain) = chain_receipt(value)? else {
        return verify_single_public_originals(
            value, originals, original, effective, network, source, version,
        );
    };
    let names = portable_record_names(value)?;
    require(
        chain.source_commit == source
            && chain.original_trust_sha256 == digest(&json::to_vec(original)?)
            && chain.effective_trust_sha256 == digest(&json::to_vec(effective)?)
            && originals.len() == names.len()
            && names.iter().all(|name| originals.contains_key(name)),
        "runtime chain selection or exact original closure differs",
    )?;
    let mut trust = original.clone();
    let mut previous: Option<(BTreeMap<String, json::Value>, String)> = None;
    let mut projections = Vec::new();
    let mut seen_sources = std::collections::BTreeSet::new();
    for (index, step) in chain.updates.iter().enumerate() {
        let receipt: PublicReceipt = json::from_value(step.clone())?;
        let step_originals = single_record_names(step)?
            .into_iter()
            .map(|name| {
                let bytes = originals[&chain_name(index, &name)].clone();
                (name, bytes)
            })
            .collect::<BTreeMap<_, _>>();
        let mut next = trust.clone();
        let fingerprint = selected_source_fingerprint(&receipt.source_commit, version)?;
        for peer in &mut next.peers {
            peer.build_fingerprint = fingerprint;
        }
        // Authenticate bounded originals before parsing any adjacency fields.
        projections.push(verify_single_public_originals(
            step,
            &step_originals,
            &trust,
            &next,
            network,
            &receipt.source_commit,
            version,
        )?);
        let records = step_originals
            .iter()
            .map(|(name, bytes)| Ok((name.clone(), json::from_slice(bytes)?)))
            .collect::<Result<BTreeMap<String, json::Value>>>()?;
        if index == 0 {
            seen_sources.insert(
                text(
                    field(field(&records["intent.json"], "deployment")?, "current")?,
                    "commit",
                )?
                .to_owned(),
            );
        }
        require(
            seen_sources.insert(receipt.source_commit.clone()),
            "runtime update chain contains a source cycle",
        )?;
        if let Some((prior, prior_digest)) = &previous {
            validate_adjacency(prior, &records, prior_digest)?;
        }
        previous = Some((records, receipt.receipt_sha256["intent.json"].clone()));
        trust = next;
    }
    retained_tip_claims(value, originals)?;
    require(
        trust == *effective && text(chain.updates.last().unwrap(), "source_commit")? == source,
        "runtime chain terminal source or trust differs",
    )?;
    Ok(
        norito::json!({"schema":"iroha.dataspace-runtime-update-chain-public-joins.v1",
        "source_commit":source,"receipt_sha256":(digest(&json::to_vec(value)?)),"updates":projections,
        "semantic_joins_verified":true,"host_custody_verified":false}),
    )
}

/// A later producer must have retained exactly the prior producer's installation.
/// Heights may advance between updates; configuration, state roots and units may not.
fn validate_adjacency(
    previous: &BTreeMap<String, json::Value>,
    next: &BTreeMap<String, json::Value>,
    previous_intent_sha256: &str,
) -> Result<()> {
    let old = &previous["intent.json"];
    let new = &next["intent.json"];
    let old_deployment = field(old, "deployment")?;
    let new_deployment = field(new, "deployment")?;
    let current = field(new_deployment, "current")?;
    let daemon = format!(
        "{BASE}/release-{}-{}/bin/iroha3d_taira",
        text(old, "commit")?,
        text(old, "operation")?
    );
    require(
        text(current, "kind")? == "completed-update"
            && text(current, "commit")? == text(old, "commit")?
            && text(current, "attempt_name")? == text(old, "operation")?
            && text(current, "daemon")? == daemon
            && text(current, "local_plan_sha256")? == previous_intent_sha256
            && text(current, "plan_schema")? == text(old, "schema")?
            && text(current, "result_schema")? == text(&previous["result.json"], "schema")?
            && text(old, "network_id")? == text(new, "network_id")?,
        "runtime chain predecessor producer identity differs",
    )?;
    // The producer's successor deployment copies all metadata except `current`.
    // Keep genesis, Kura location, config and routing bound to the original installation.
    let mut prior_deployment = old_deployment.clone();
    let mut next_deployment = new_deployment.clone();
    prior_deployment
        .as_object_mut()
        .ok_or_else(|| eyre!("runtime deployment is not an object"))?
        .remove("current");
    next_deployment
        .as_object_mut()
        .ok_or_else(|| eyre!("runtime deployment is not an object"))?
        .remove("current");
    require(
        prior_deployment == next_deployment,
        "runtime chain retained deployment differs",
    )?;
    config_filename(old_deployment)?;
    config_filename(new_deployment)?;
    let old_units = rows(field(old, "units")?)?;
    let new_units = rows(field(new, "units")?)?;
    let final_rows = rows(field(&previous["cohort-ready.json"], "observations")?)?;
    let initial_rows = rows(&next["retained-entry.json"])?;
    require(
        [
            old_units.len(),
            new_units.len(),
            final_rows.len(),
            initial_rows.len(),
        ]
        .iter()
        .all(|n| *n == 4),
        "runtime chain cohort count differs",
    )?;
    for index in 0..4 {
        require(
            field(&old_units[index], "after")? == field(&new_units[index], "before")?
                && field(&old_units[index], "after_sha256")?
                    == field(&new_units[index], "before_sha256")?,
            "runtime chain units are not adjacent",
        )?;
        for key in [
            "role",
            "state_root_identity",
            "current_target",
            "config_stamp",
        ] {
            require(
                field(&final_rows[index], key)? == field(&initial_rows[index], key)?,
                "runtime chain changed retained peer custody",
            )?;
        }
        let before = field(&initial_rows[index], "public")?;
        let prior = field(&final_rows[index], "public")?;
        require(
            text(before, "commit")? == text(prior, "commit")?
                && text(before, "network_id")? == text(prior, "network_id")?
                && number(before, "height")? >= number(prior, "height")?,
            "runtime chain predecessor public identity or height differs",
        )?;
    }
    Ok(())
}

/// Runtime receipt claims awaiting comparison with an authenticated protocol prefix.
/// These values do not authenticate blocks or establish host custody themselves.
#[derive(Default)]
pub(super) struct RetainedTips {
    hashes: BTreeMap<u64, Hash>,
    peer_heights: [u64; 4],
    checkpoint_count: usize,
}

fn checkpoint_tips(record: &json::Value) -> Result<Vec<(u64, Hash)>> {
    let records = rows(record)?;
    require(records.len() == 4, "runtime retained tip cohort differs")?;
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            require(
                text(record, "role")? == format!("taira-validator-{}", index + 1),
                "runtime retained tip role differs",
            )?;
            let tip = field(record, "kura_tip")?;
            let height = number(tip, "height")?;
            let raw = text(tip, "hash")?;
            require(
                height > 0
                    && raw.len() == 64
                    && raw
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "runtime retained tip height or hash is malformed",
            )?;
            let mut bytes = [0u8; Hash::LENGTH];
            hex::decode_to_slice(raw, &mut bytes)?;
            let hash = Hash::from_marked_bytes(bytes)
                .ok_or_else(|| eyre!("runtime retained block hash has no Iroha marker"))?;
            Ok((height, hash))
        })
        .collect()
}

impl RetainedTips {
    /// Collect bounded chronological checkpoint claims without granting authority.
    pub(super) fn from_checkpoint_records<'a>(
        records: impl IntoIterator<Item = &'a json::Value>,
    ) -> Result<Self> {
        let mut value = Self::default();
        for record in records {
            value.append_checkpoint(record)?;
        }
        Ok(value)
    }

    fn append_checkpoint(&mut self, record: &json::Value) -> Result<()> {
        require(
            self.checkpoint_count < MAX_UPDATES,
            "runtime retained tip chain exceeds bound",
        )?;
        for (peer, (height, hash)) in checkpoint_tips(record)?.into_iter().enumerate() {
            require(
                height >= self.peer_heights[peer],
                "runtime retained tip regressed",
            )?;
            if let Some(prior) = self.hashes.insert(height, hash) {
                require(
                    prior == hash,
                    "runtime retained tips conflict at one height",
                )?;
            }
            self.peer_heights[peer] = height;
        }
        self.checkpoint_count += 1;
        Ok(())
    }

    /// Heights that portable replay must retain from its authenticated proof walk.
    pub(super) fn heights(&self) -> impl Iterator<Item = u64> + '_ {
        self.hashes.keys().copied()
    }

    /// Match all claims only after the existing genesis/QC verifier authenticated
    /// this prefix. Missing historical heights fail; no receipt extends the prefix.
    pub(super) fn verify_authenticated_prefix(
        &self,
        proofs: &BTreeMap<u64, iroha_data_model::sumeragi_finality::SumeragiFinalityProof>,
        current_peer_heights: impl IntoIterator<Item = u64>,
    ) -> Result<()> {
        let current = current_peer_heights.into_iter().collect::<Vec<_>>();
        require(
            current.len() == 4
                && self
                    .peer_heights
                    .iter()
                    .zip(&current)
                    .all(|(retained, current)| retained <= current),
            "runtime retained tip exceeds its peer's signed current height",
        )?;
        for (&height, expected) in &self.hashes {
            let proof = proofs
                .get(&height)
                .ok_or_else(|| eyre!("runtime retained tip is outside the authenticated prefix"))?;
            require(
                proof.block_header.height().get() == height
                    && Hash::from(proof.block_header.hash()) == *expected,
                "runtime retained block hash differs from authenticated finality",
            )?;
        }
        Ok(())
    }
}

/// Read claims from the exact hash-bound checkpoint originals. The caller first
/// verifies all runtime semantic joins; these claims still require protocol proofs.
pub(super) fn retained_tip_claims(
    value: &json::Value,
    originals: &BTreeMap<String, Vec<u8>>,
) -> Result<RetainedTips> {
    let names = portable_record_names(value)?;
    require(
        originals.len() == names.len() && names.iter().all(|name| originals.contains_key(name)),
        "runtime retained tip original closure differs",
    )?;
    let chain = chain_receipt(value)?;
    let steps = chain.as_ref().map_or_else(
        || std::slice::from_ref(value),
        |chain| chain.updates.as_slice(),
    );
    let mut claims = RetainedTips::default();
    for (index, step) in steps.iter().enumerate() {
        let receipt: PublicReceipt = json::from_value(step.clone())?;
        let name = if chain.is_some() {
            chain_name(index, "checkpoint-stopped.json")
        } else {
            "checkpoint-stopped.json".into()
        };
        let bytes = &originals[&name];
        require(
            bytes.len() <= MAX_BYTES
                && digest(bytes) == receipt.receipt_sha256["checkpoint-stopped.json"],
            "runtime retained checkpoint original changed",
        )?;
        let checkpoint = json::from_slice::<json::Value>(bytes)?;
        claims.append_checkpoint(&checkpoint)?;
    }
    Ok(claims)
}

fn config_filename(deployment: &json::Value) -> Result<&str> {
    let filename = match deployment.get("config_filename") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| eyre!("runtime config filename differs"))?,
        None => "config.toml",
    };
    require(
        matches!(filename, "config.toml" | "beacon.toml"),
        "runtime config filename differs",
    )?;
    Ok(filename)
}

fn field<'a>(value: &'a json::Value, name: &str) -> Result<&'a json::Value> {
    value
        .get(name)
        .ok_or_else(|| eyre!("runtime update evidence field missing: {name}"))
}
fn text<'a>(value: &'a json::Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| eyre!("runtime update text field differs: {name}"))
}
fn rows(value: &json::Value) -> Result<&Vec<json::Value>> {
    value
        .as_array()
        .ok_or_else(|| eyre!("runtime update cohort is not an array"))
}
fn flag(value: &json::Value, name: &str, expected: bool) -> Result<()> {
    require(
        field(value, name)?.as_bool() == Some(expected),
        "runtime update completion claim differs",
    )
}
fn number(value: &json::Value, name: &str) -> Result<u64> {
    field(value, name)?
        .as_u64()
        .ok_or_else(|| eyre!("runtime update integer field differs: {name}"))
}

fn authenticated_replay_height(events: &json::Value) -> Result<u64> {
    let events = rows(events)?;
    require(events.len() <= 64, "runtime replay event bound exceeded")?;
    let mut failed = Vec::new();
    let mut begun = Vec::new();
    let mut completed = Vec::new();
    for event in events {
        let message = text(event, "message")?;
        require(
            ![
                "creating an empty state",
                "Snapshot restore is disabled",
                "emergency Fast",
                "Successfully loaded the state from a snapshot",
                "Validated snapshot block hashes against Kura",
            ]
            .iter()
            .any(|value| message.contains(value)),
            "runtime replay has a foreign or mixed startup mode",
        )?;
        if message.contains("Failed to load state snapshot") {
            failed.push(event);
        }
        if message.contains(
            "Kura retains the configured-primary replay floor; rebuilding state from blocks",
        ) {
            begun.push(event);
        }
        if message.contains("Sumeragi rebuilt the state from genesis and Kura") {
            completed.push(event);
        }
    }
    require(
        failed.len() == 1 && begun.len() == 1 && completed.len() == 1,
        "runtime native replay sequence differs",
    )?;
    require(
        text(failed[0], "message")?.split_whitespace().last()
            == Some("error=NativeExecutionReplayRequired")
            && number(failed[0], "time_us")? > 0
            && number(failed[0], "time_us")? <= number(begun[0], "time_us")?
            && number(begun[0], "time_us")? <= number(completed[0], "time_us")?,
        "runtime native replay policy or event order differs",
    )?;
    let heights = text(completed[0], "message")?
        .split_whitespace()
        .filter_map(|word| word.strip_prefix("height="))
        .collect::<Vec<_>>();
    require(
        heights.len() == 1
            && !heights[0].is_empty()
            && heights[0].bytes().all(|byte| byte.is_ascii_digit()),
        "runtime native replay completion height missing",
    )?;
    let height = heights[0].parse()?;
    require(height > 0, "runtime native replay completion is empty")?;
    Ok(height)
}

fn verify_restored_record(
    restored: &json::Value,
    stopped: &json::Value,
    after: &json::Value,
    source: &str,
    network: NetworkId,
    modern: bool,
) -> Result<bool> {
    if field(restored, "native_strict_checkpoint_verified")?.as_bool() == Some(true) {
        require(
            ![
                "proof_kind",
                "native_authenticated_kura_replay_verified",
                "retained_kura_tip",
                "source_commit",
                "network_id",
            ]
            .iter()
            .any(|key| restored.get(*key).is_some()),
            "Strict restore receipt cannot claim native replay",
        )?;
        return Ok(true);
    }
    require(modern, "legacy runtime requires native Strict restoration")?;
    flag(restored, "native_strict_checkpoint_verified", false)?;
    flag(restored, "native_authenticated_kura_replay_verified", true)?;
    require(
        text(restored, "proof_kind")? == "native_authenticated_kura_replay"
            && text(restored, "source_commit")? == source
            && text(restored, "network_id")? == network.to_string()
            && field(restored, "retained_kura_tip")? == field(stopped, "kura_tip")?,
        "runtime native replay retained identity differs",
    )?;
    let height = authenticated_replay_height(field(restored, "events")?)?;
    require(
        number(restored, "restored_height")? == height
            && height >= number(field(stopped, "kura_tip")?, "height")?
            && number(field(after, "public")?, "height")? >= height,
        "runtime native replay retained height differs",
    )?;
    let ready = field(after, "cohort_observation")?;
    flag(ready, "ready", true)?;
    flag(ready, "public_fresh", true)?;
    Ok(false)
}

/// Pure receipt joins are tested independently of privileged filesystem observation.
fn validate_records(
    records: &BTreeMap<String, json::Value>,
    operation: &str,
    network: NetworkId,
    source: &str,
    original: &DeploymentTrustV1,
    version: &str,
) -> Result<()> {
    let plan = &records["intent.json"];
    let result = &records["result.json"];
    let retirement = match (
        records.get("config-retirement-prepared.json"),
        records.get("config-retirement-installed.json"),
    ) {
        (Some(prepared), Some(installed)) => {
            crate::taira_public_reset::validate_retirement_records(prepared, installed, plan)?;
            Some(rows(field(installed, "rows")?)?)
        }
        (None, None) => None,
        _ => return Err(eyre!("runtime config retirement evidence is incomplete")),
    };
    let deployment = field(plan, "deployment")?;
    require(
        matches!(
            text(plan, "schema")?,
            "taira.daemon-update.plan.v1" | "taira.daemon-update.plan.v2"
        ) && text(result, "schema")? == text(plan, "schema")?.replace(".plan.", ".result.")
            && text(plan, "operation")? == operation
            && text(plan, "commit")? == source
            && text(result, "commit")? == source
            && text(plan, "network_id")? == network.to_string()
            && text(result, "network_id")? == network.to_string()
            && text(deployment, "network_id")? == network.to_string()
            && text(deployment, "runtime_root")? == BASE
            && text(deployment, "config_root")? == "/srv/taira"
            && text(deployment, "state_root")? == "/var/lib/taira",
        "runtime update source, network or retained roots differ",
    )?;
    for name in [
        "runtime_update_complete",
        "state_preserved",
        "cohort_processes_verified_after_final_observation",
        "all_own_retained_tips_verified_after_final_observation",
    ] {
        flag(result, name, true)?;
    }
    let modern = text(plan, "schema")? == "taira.daemon-update.plan.v2";
    let mut recovery_modes = Vec::new();
    for name in [
        "secret_contents_read",
        "transaction_submission",
        "python_transaction_submission",
    ] {
        flag(plan, name, false)?;
    }
    require(
        plan.get("failed_start").is_none(),
        "runtime verification does not reinterpret failed-start ancestry",
    )?;
    let previous = text(field(deployment, "current")?, "commit")?;
    require(
        previous != source
            && previous.len() == 40
            && previous
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "runtime update predecessor source differs",
    )?;
    let prior_fingerprint = Hash::new([version.as_bytes(), previous.as_bytes()].concat());
    require(
        original.peers.len() == 4
            && original
                .peers
                .iter()
                .all(|p| p.build_fingerprint == prior_fingerprint),
        "original peer build pins do not match the retained predecessor",
    )?;
    let units = rows(field(plan, "units")?)?;
    let artifacts = rows(field(plan, "artifacts")?)?;
    require(
        units.len() == 4 && artifacts.len() == 3,
        "runtime update artifact or cohort count differs",
    )?;
    for (artifact, expected) in artifacts.iter().zip(["iroha3d_taira", "iroha", "kagami"]) {
        require(
            text(artifact, "name")? == expected
                && text(artifact, "sha256")?.len() == 64
                && field(artifact, "size")?
                    .as_u64()
                    .is_some_and(|n| n > 1_000_000 && n < 1024 * 1024 * 1024),
            "runtime update artifact identity differs",
        )?;
    }
    let retained_tips = checkpoint_tips(&records["checkpoint-stopped.json"])?;
    let final_rows = rows(field(&records["cohort-ready.json"], "observations")?)?;
    for name in [
        "retained-entry.json",
        "after.json",
        "checkpoint-stopped.json",
        "checkpoint-restored.json",
    ] {
        require(
            rows(&records[name])?.len() == 4,
            "runtime update retained cohort count differs",
        )?;
    }
    require(
        final_rows.len() == 4,
        "runtime update final cohort count differs",
    )?;
    for index in 0..4 {
        let role = format!("taira-validator-{}", index + 1);
        let before = &rows(&records["retained-entry.json"])?[index];
        let after = &rows(&records["after.json"])?[index];
        let stopped = &rows(&records["checkpoint-stopped.json"])?[index];
        let restored = &rows(&records["checkpoint-restored.json"])?[index];
        for row in [
            &units[index],
            before,
            after,
            stopped,
            restored,
            &final_rows[index],
        ] {
            require(
                text(row, "role")? == role,
                "runtime update role ordering differs",
            )?;
        }
        let before_unit =
            base64::engine::general_purpose::STANDARD.decode(text(&units[index], "before")?)?;
        let after_unit =
            base64::engine::general_purpose::STANDARD.decode(text(&units[index], "after")?)?;
        let current = field(deployment, "current")?;
        let old =
            if current.get("kind").and_then(json::Value::as_str) == Some("observed-installation") {
                text(field(field(current, "daemons")?, &role)?, "command")?
            } else {
                text(current, "daemon")?
            };
        require(!old.is_empty(), "runtime predecessor daemon is empty")?;
        let positions: Vec<_> = before_unit
            .windows(old.len())
            .enumerate()
            .filter_map(|(i, bytes)| (bytes == old.as_bytes()).then_some(i))
            .collect();
        require(
            !old.is_empty()
                && positions.len() == 1
                && before_unit.len() <= 128 * 1024
                && digest(&before_unit) == text(&units[index], "before_sha256")?
                && digest(&after_unit) == text(&units[index], "after_sha256")?,
            "runtime unit transition digest differs",
        )?;
        let pos = positions[0];
        let candidate = format!("{BASE}/release-{source}-{operation}/bin/iroha3d_taira");
        let expected = [
            &before_unit[..pos],
            candidate.as_bytes(),
            &before_unit[pos + old.len()..],
        ]
        .concat();
        require(
            expected == after_unit,
            "runtime unit transition exceeds the daemon argument",
        )?;
        flag(stopped, "cohort_stopped", true)?;
        require(
            retained_tips[index].0 >= number(stopped, "checkpoint_height")?
                && retained_tips[index].0 >= number(field(before, "public")?, "height")?,
            "runtime stopped tip predates its retained observation",
        )?;
        let strict = verify_restored_record(restored, stopped, after, source, network, modern)?;
        if !strict {
            let final_ready = field(&final_rows[index], "cohort_observation")?;
            flag(final_ready, "ready", true)?;
            flag(final_ready, "public_fresh", true)?;
        }
        recovery_modes.push(if strict {
            "native_strict_restore"
        } else {
            "native_authenticated_kura_replay"
        });
        require(
            number(restored, "restored_height")? >= number(stopped, "checkpoint_height")?
                && number(stopped, "checkpoint_height")? > 0,
            "runtime update did not restore its retained checkpoint",
        )?;
        for key in ["state_root_identity", "current_target"] {
            require(
                field(before, key)? == field(after, key)?
                    && field(after, key)? == field(&final_rows[index], key)?,
                "runtime update changed retained state custody",
            )?;
        }
        let expected_config = if let Some(retirement) = retirement {
            let row = &retirement[index];
            require(
                field(before, "config_stamp")? == field(row, "before_stamp")?,
                "runtime config retirement predecessor differs",
            )?;
            field(row, "installed_stamp")?
        } else {
            field(before, "config_stamp")?
        };
        require(
            expected_config == field(after, "config_stamp")?
                && expected_config == field(&final_rows[index], "config_stamp")?,
            "runtime update changed retained config without native retirement",
        )?;
        for row in [after, &final_rows[index]] {
            let public = field(row, "public")?;
            require(
                text(public, "commit")? == source
                    && text(public, "network_id")? == network.to_string()
                    && number(public, "height")? >= number(field(stopped, "kura_tip")?, "height")?
                    && number(field(stopped, "kura_tip")?, "height")? > 0,
                "runtime update final public identity or retained height differs",
            )?;
        }
        for key in ["MainPID", "InvocationID", "NRestarts"] {
            require(
                field(field(after, "systemd")?, key)?
                    == field(field(&final_rows[index], "systemd")?, key)?,
                "runtime update final process differs",
            )?;
        }
    }
    let strict = recovery_modes
        .iter()
        .all(|mode| *mode == "native_strict_restore");
    flag(result, "retained_native_snapshot_verified", strict)?;
    if modern {
        flag(result, "retained_native_state_verified", true)?;
        flag(result, "historical_genesis_replay_supported", !strict)?;
        let modes = rows(field(result, "native_recovery_modes")?)?;
        require(
            modes.len() == 4
                && modes
                    .iter()
                    .zip(&recovery_modes)
                    .all(|(value, mode)| value.as_str() == Some(*mode)),
            "runtime completion recovery mode differs",
        )?;
    }
    Ok(())
}

fn verify_artifact(artifact: &json::Value, actual_sha256: &str, actual_size: u64) -> Result<()> {
    require(
        text(artifact, "sha256")? == actual_sha256 && number(artifact, "size")? == actual_size,
        "runtime artifact digest or size differs",
    )
}

fn verify_process(
    observed: &BTreeMap<String, String>,
    expected: &json::Value,
    fragment: &Path,
) -> Result<()> {
    for (key, expected) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("ControlPID", "0"),
        ("DropInPaths", ""),
        ("NeedDaemonReload", "no"),
        ("Job", ""),
    ] {
        require(
            observed.get(key).map(String::as_str) == Some(expected),
            "runtime process is not the exact healthy cohort",
        )?;
    }
    require(
        observed.get("FragmentPath").map(String::as_str) == fragment.to_str(),
        "runtime systemd fragment differs",
    )?;
    for key in ["MainPID", "InvocationID", "NRestarts"] {
        require(
            observed.get(key).map(String::as_str) == Some(text(expected, key)?),
            "runtime process identity changed",
        )?;
    }
    Ok(())
}

pub(super) struct Verified {
    pub(super) source_commit: String,
    pub(super) source_version: String,
    pub(super) trust: DeploymentTrustV1,
    pub(super) receipt: json::Value,
    #[cfg(target_os = "linux")]
    held: Vec<PublicInput>,
    #[cfg(target_os = "linux")]
    records: BTreeMap<String, json::Value>,
    #[cfg(target_os = "linux")]
    directory: PathBuf,
    #[cfg(target_os = "linux")]
    binaries: Vec<(PathBuf, File, fs::Metadata)>,
    #[cfg(target_os = "linux")]
    installed: bool,
    #[cfg(target_os = "linux")]
    historical: Vec<Self>,
}

#[cfg(target_os = "linux")]
fn root_path(path: &Path, directory: bool) -> Result<fs::Metadata> {
    use std::os::unix::fs::MetadataExt as _;
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "runtime evidence path is indirect",
    )?;
    for ancestor in path.ancestors().skip(1) {
        let meta = fs::symlink_metadata(ancestor)?;
        require(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "runtime evidence ancestor custody differs",
        )?;
    }
    let meta = fs::symlink_metadata(path)?;
    require(
        meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file() && meta.nlink() == 1
            },
        "runtime evidence owner or file kind differs",
    )?;
    Ok(meta)
}

#[cfg(unix)]
fn metadata_value(meta: &fs::Metadata) -> Result<json::Value> {
    use std::os::unix::fs::MetadataExt as _;
    let timestamp = |seconds: i64, nanos: i64| -> Result<u64> {
        let value = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
        u64::try_from(value)
            .map_err(|_| eyre!("runtime metadata timestamp is outside the supported range"))
    };
    Ok(json::to_value(&vec![
        meta.dev(),
        meta.ino(),
        u64::from(meta.mode()),
        u64::from(meta.uid()),
        u64::from(meta.gid()),
        meta.nlink(),
        meta.len(),
        timestamp(meta.mtime(), meta.mtime_nsec())?,
        timestamp(meta.ctime(), meta.ctime_nsec())?,
    ])?)
}

#[cfg(target_os = "linux")]
fn process(role: &str) -> Result<BTreeMap<String, String>> {
    let result = std::process::Command::new("/usr/bin/systemctl").args(["show", "--all",
        "--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job",
        &format!("iroha3d-{role}.service")]).output()?;
    require(
        result.status.success() && result.stdout.len() <= 65536,
        "runtime process observation failed",
    )?;
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| eyre!("invalid runtime process observation"))?;
        require(
            values.insert(key.into(), value.into()).is_none(),
            "duplicate runtime process observation",
        )?;
    }
    require(
        values.len() == 11,
        "runtime process observation fields differ",
    )?;
    Ok(values)
}

impl Verified {
    /// Authenticate an ordered, bounded update history without replacing the
    /// original trust. Only the last update must still be the live installation.
    pub(super) fn admit_chain(
        paths: &[PathBuf],
        original: &DeploymentTrustV1,
        network: NetworkId,
        selected: Option<(&str, &str)>,
    ) -> Result<Self> {
        validate_selection(paths)?;
        require(!paths.is_empty(), "runtime update selection is empty")?;
        if paths.len() == 1 {
            return match selected {
                Some((source, version)) => {
                    Self::admit_target(&paths[0], original, network, source, version)
                }
                None => Self::admit(&paths[0], original, network),
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            eyre::bail!("runtime update verification requires the actual Linux validator guest");
        }
        #[cfg(target_os = "linux")]
        {
            let identity = if selected.is_none() {
                Some(crate::compiled_build_identity()?)
            } else {
                None
            };
            let (source, version) = match selected {
                Some(target) => target,
                None => {
                    let identity = identity.as_ref().expect("compiled target was selected");
                    (identity.release_source_commit()?, identity.version())
                }
            };
            selected_source_fingerprint(source, version)?;
            let mut steps = Vec::new();
            let mut trust = original.clone();
            for (index, path) in paths.iter().enumerate() {
                let installed = index + 1 == paths.len();
                let step = Self::admit_selected(
                    path,
                    &trust,
                    network,
                    installed.then_some(source),
                    version,
                    installed && selected.is_none(),
                    installed,
                )?;
                trust = step.trust.clone();
                steps.push(step);
            }
            let receipt = norito::json!({"schema":CHAIN_SCHEMA,"source_commit":source,
                "original_trust_sha256":(digest(&json::to_vec(original)?)),
                "effective_trust_sha256":(digest(&json::to_vec(&trust)?)),
                "updates":(steps.iter().map(|step| step.receipt.clone()).collect::<Vec<_>>()),
                "chain_write_performed":false});
            let mut value = steps.pop().expect("bounded nonempty chain");
            value.receipt = receipt;
            value.historical = steps;
            // The same maintained portable joins enforce every producer edge.
            // Live admission adds custody, retained binaries and terminal process checks.
            let originals = value.public_originals()?;
            verify_public_originals(
                &value.receipt,
                &originals,
                original,
                &value.trust,
                network,
                source,
                version,
            )?;
            value.revalidate()?;
            Ok(value)
        }
    }

    /// Export only exact already-admitted public originals. Private configurations
    /// and measured binaries remain in the actual Linux custody verifier.
    pub(super) fn public_originals(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        #[cfg(not(target_os = "linux"))]
        {
            eyre::bail!("runtime public originals require admitted Linux custody");
        }
        #[cfg(target_os = "linux")]
        {
            self.revalidate()?;
            let mut originals = BTreeMap::new();
            let steps = self.historical.iter().chain(std::iter::once(self));
            let chain = chain_receipt(&self.receipt)?;
            for (index, step) in steps.enumerate() {
                let receipt = chain
                    .as_ref()
                    .map_or(&step.receipt, |chain| &chain.updates[index]);
                let names = single_record_names(receipt)?;
                let receipt: PublicReceipt = json::from_value(receipt.clone())?;
                for name in names {
                    let input = PublicInput::read(&step.directory.join(&name))?;
                    require(
                        digest(&input.bytes) == receipt.receipt_sha256[&name],
                        "runtime public original changed",
                    )?;
                    input.revalidate()?;
                    originals.insert(
                        if chain.is_some() {
                            chain_name(index, &name)
                        } else {
                            name
                        },
                        input.bytes,
                    );
                }
            }
            self.revalidate()?;
            Ok(originals)
        }
    }
    pub(super) fn admit(
        path: &Path,
        original: &DeploymentTrustV1,
        network: NetworkId,
    ) -> Result<Self> {
        let identity = crate::compiled_build_identity()?;
        Self::admit_selected(
            path,
            original,
            network,
            Some(identity.release_source_commit()?),
            identity.version(),
            true,
            true,
        )
    }

    /// Read-only target admission by a separately authenticated verifier. This
    /// changes only how the target build identity is selected: the exact Linux
    /// candidate binaries, root-owned originals and live cohort remain mandatory.
    pub(super) fn admit_target(
        path: &Path,
        original: &DeploymentTrustV1,
        network: NetworkId,
        source: &str,
        version: &str,
    ) -> Result<Self> {
        Self::admit_selected(path, original, network, Some(source), version, false, true)
    }

    fn admit_selected(
        path: &Path,
        original: &DeploymentTrustV1,
        network: NetworkId,
        source: Option<&str>,
        version: &str,
        require_candidate_executable: bool,
        installed: bool,
    ) -> Result<Self> {
        if let Some(source) = source {
            selected_source_fingerprint(source, version)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                path,
                original,
                network,
                source,
                version,
                require_candidate_executable,
                installed,
            );
            eyre::bail!("runtime update verification requires the actual Linux validator guest");
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Read as _;
            use std::os::unix::fs::MetadataExt as _;
            require(
                rustix::process::geteuid().as_raw() == 0,
                "runtime update verification requires root metadata custody",
            )?;
            let operation = operation_name(path)?;
            require(
                root_path(path, true)?.mode() & 0o7777 == 0o700,
                "runtime operation must remain root-private",
            )?;
            let mut held = Vec::new();
            let mut records = BTreeMap::new();
            let mut hashes = BTreeMap::new();
            for name in RECORDS {
                let selected = path.join(name);
                require(
                    root_path(&selected, false)?.mode() & 0o7777 == 0o600,
                    "runtime receipt must remain root-private",
                )?;
                let input = PublicInput::read(&selected)?;
                hashes.insert(name.to_owned(), digest(&input.bytes));
                records.insert(name.to_owned(), json::from_slice(&input.bytes)?);
                held.push(input);
            }
            for name in [
                "config-retirement-prepared.json",
                "config-retirement-installed.json",
            ] {
                let selected = path.join(name);
                match fs::symlink_metadata(&selected) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                    Ok(_) => {}
                }
                require(
                    root_path(&selected, false)?.mode() & 0o7777 == 0o600,
                    "runtime config retirement receipt custody differs",
                )?;
                let input = PublicInput::read(&selected)?;
                hashes.insert(name.to_owned(), digest(&input.bytes));
                records.insert(name.to_owned(), json::from_slice(&input.bytes)?);
                held.push(input);
            }
            // A historical target comes from its held root-private producer original.
            // The terminal target is still independently selected or compiled in.
            let source = source.unwrap_or(text(&records["intent.json"], "commit")?);
            let fingerprint = selected_source_fingerprint(source, version)?;
            validate_records(&records, operation, network, source, original, version)?;
            let release = Path::new(BASE).join(format!("release-{source}-{operation}/bin"));
            require(
                !require_candidate_executable || std::env::current_exe()? == release.join("iroha"),
                "runtime verifier is not the actual prepared candidate CLI",
            )?;
            let mut binaries = Vec::new();
            for artifact in rows(field(&records["intent.json"], "artifacts")?)? {
                let path = release.join(text(artifact, "name")?);
                let snapshot = root_path(&path, false)?;
                require(
                    snapshot.len() == field(artifact, "size")?.as_u64().unwrap_or(0)
                        && snapshot.mode() & 0o111 != 0,
                    "runtime artifact size differs",
                )?;
                let mut file = File::from(rustix::fs::open(
                    &path,
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )?);
                let mut hash = Sha256::new();
                let mut buffer = [0u8; 65536];
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buffer[..n]);
                }
                verify_artifact(artifact, &hex::encode(hash.finalize()), snapshot.len())?;
                require(
                    same_file_snapshot(&snapshot, &file.metadata()?)
                        && same_file_snapshot(&snapshot, &root_path(&path, false)?),
                    "runtime artifact digest or custody differs",
                )?;
                binaries.push((path, file, snapshot));
            }
            let mut trust = original.clone();
            for peer in &mut trust.peers {
                peer.build_fingerprint = fingerprint;
            }
            let receipt = norito::json!({"schema":"iroha.dataspace-runtime-update-verification.v1",
                "operation_directory":(path.to_string_lossy().into_owned()), "source_commit":source,
                "receipt_sha256":hashes, "original_trust_sha256":(digest(&json::to_vec(original)?)),
                "effective_trust_sha256":(digest(&json::to_vec(&trust)?)), "chain_write_performed":false});
            let value = Self {
                source_commit: source.to_owned(),
                source_version: version.to_owned(),
                trust,
                receipt,
                held,
                records,
                directory: path.into(),
                binaries,
                installed,
                historical: Vec::new(),
            };
            value.revalidate()?;
            Ok(value)
        }
    }

    /// Retained producer claims, compared with authenticated finality before completion.
    pub(super) fn retained_tip_claims(&self) -> Result<RetainedTips> {
        #[cfg(not(target_os = "linux"))]
        {
            eyre::bail!("runtime retained tips require admitted Linux custody");
        }
        #[cfg(target_os = "linux")]
        {
            RetainedTips::from_checkpoint_records(
                self.historical
                    .iter()
                    .chain(std::iter::once(self))
                    .map(|step| &step.records["checkpoint-stopped.json"]),
            )
        }
    }

    pub(super) fn revalidate(&self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            eyre::bail!("runtime update verification requires Linux");
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;
            for step in &self.historical {
                step.revalidate()?;
            }
            require(
                root_path(&self.directory, true)?.mode() & 0o7777 == 0o700,
                "runtime operation must remain root-private",
            )?;
            for input in &self.held {
                input.revalidate()?;
            }
            for name in RECORDS.into_iter().chain([
                "config-retirement-prepared.json",
                "config-retirement-installed.json",
            ]) {
                let path = self.directory.join(name);
                if self.records.contains_key(name) {
                    require(
                        root_path(&path, false)?.mode() & 0o7777 == 0o600,
                        "runtime receipt must remain root-private",
                    )?;
                } else {
                    require(
                        fs::symlink_metadata(path)
                            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                        "runtime retirement inventory changed",
                    )?;
                }
            }
            for (path, file, snapshot) in &self.binaries {
                require(
                    same_file_snapshot(snapshot, &file.metadata()?)
                        && same_file_snapshot(snapshot, &root_path(path, false)?),
                    "runtime artifact custody changed",
                )?;
            }
            for name in [
                "failure.json",
                "rollback.json",
                "config-retirement-restored.json",
            ] {
                require(
                    fs::symlink_metadata(self.directory.join(name))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "runtime update has a failure or rollback marker",
                )?;
            }
            if !self.installed {
                return Ok(());
            }
            let plan = &self.records["intent.json"];
            if let Some(prepared) = self.records.get("config-retirement-prepared.json") {
                let installed = self
                    .records
                    .get("config-retirement-installed.json")
                    .ok_or_else(|| eyre!("runtime config retirement completion missing"))?;
                crate::taira_public_reset::verify_installed_retirement(prepared, installed, plan)?;
                require(
                    fs::symlink_metadata(self.directory.join("config-retirement-restored.json"))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "runtime config retirement was restored",
                )?;
            }
            let deployment = field(plan, "deployment")?;
            let release = text(deployment, "config_release")?;
            require(
                release.len() == 40 && release.bytes().all(|b| b.is_ascii_hexdigit()),
                "runtime retained config revision differs",
            )?;
            let filename = config_filename(deployment)?;
            let daemon = &self.binaries[0].0;
            let final_rows = rows(field(&self.records["cohort-ready.json"], "observations")?)?;
            for index in 0..4 {
                let role = format!("taira-validator-{}", index + 1);
                let unit = &rows(field(plan, "units")?)?[index];
                let after = &final_rows[index];
                let fragment = PathBuf::from(format!("/etc/systemd/system/iroha3d-{role}.service"));
                root_path(&fragment, false)?;
                let raw = PublicInput::read(&fragment)?;
                require(
                    raw.bytes
                        == base64::engine::general_purpose::STANDARD
                            .decode(text(unit, "after")?)?
                        && digest(&raw.bytes) == text(unit, "after_sha256")?,
                    "installed runtime unit differs",
                )?;
                let target = PathBuf::from(format!("/srv/taira/{role}/releases/{release}"));
                let selector = PathBuf::from(format!("/srv/taira/{role}/current"));
                require(
                    fs::symlink_metadata(&selector)?.uid() == 0
                        && fs::read_link(&selector)? == target
                        && text(after, "current_target")? == target.to_string_lossy(),
                    "runtime config selector changed",
                )?;
                require(
                    metadata_value(&root_path(&target.join("config").join(filename), false)?)?
                        == *field(after, "config_stamp")?,
                    "retained runtime config metadata changed",
                )?;
                let state = root_path(&PathBuf::from(format!("/var/lib/taira/{role}")), true)?;
                require(
                    json::to_value(&vec![state.dev(), state.ino()])?
                        == *field(after, "state_root_identity")?,
                    "retained state root changed",
                )?;
                let observed = process(&role)?;
                verify_process(&observed, field(after, "systemd")?, &fragment)?;
                let pid: u32 = observed["MainPID"].parse()?;
                require(pid > 0, "runtime PID missing")?;
                let proc = PathBuf::from(format!("/proc/{pid}"));
                let expected = format!(
                    "{}\0--config\0{}/config/{filename}\0--sora\0",
                    daemon.display(),
                    selector.display()
                );
                require(
                    fs::read_link(proc.join("exe"))? == *daemon
                        && fs::read(proc.join("cmdline"))? == expected.as_bytes(),
                    "runtime executable or process arguments differ",
                )?;
                raw.revalidate()?;
                require(
                    process(&role)? == observed,
                    "runtime process changed during verification",
                )?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
pub(super) fn test_transition_trust() -> DeploymentTrustV1 {
    // Receipt-join tests do not execute or authenticate genesis. Full finality
    // authentication remains the existing production verifier's responsibility.
    let key = |seed| {
        iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap()
    };
    DeploymentTrustV1 {
        chain: "fc56984b-2be7-431d-840e-21514d1883f0".into(),
        account_chain_discriminant: 369,
        genesis_public_key: key(9).public_key().clone(),
        genesis_signed_wire_hex: String::new(),
        peers: (1..=4)
            .map(|seed| finality::PeerV1 {
                torii_origin: format!("http://127.0.0.1:{}/", 8080 + u16::from(seed)),
                peer_id: iroha_model_base::peer::PeerId::new(key(seed).public_key().clone()),
                node_fingerprint: Hash::new([seed]),
                build_fingerprint: Hash::new([1]),
                config_fingerprint: Hash::new([2]),
            })
            .collect(),
    }
}

#[cfg(test)]
pub(super) fn test_chain_retained_tip_claims(height: u64, hash: Hash) -> Result<RetainedTips> {
    tests::chain_retained_tip_claims(height, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "2222222222222222222222222222222222222222";
    const PREVIOUS: &str = "1111111111111111111111111111111111111111";
    const VERSION: &str = "2.0.0-rc.2.0";

    fn fixture() -> (
        BTreeMap<String, json::Value>,
        String,
        NetworkId,
        DeploymentTrustV1,
    ) {
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new("receipt-join-fixture"),
        ));
        let mut trust = test_transition_trust();
        for peer in &mut trust.peers {
            peer.build_fingerprint = Hash::new(format!("{VERSION}{PREVIOUS}"));
        }
        let operation = format!("update-{}", "a".repeat(32));
        let old = format!("{BASE}/previous/bin/iroha3d_taira");
        let candidate = format!("{BASE}/release-{SOURCE}-{operation}/bin/iroha3d_taira");
        let mut units = Vec::new();
        let mut before = Vec::new();
        let mut after = Vec::new();
        let mut stopped = Vec::new();
        let mut restored = Vec::new();
        for index in 1..=4 {
            let role = format!("taira-validator-{index}");
            let raw = format!(
                "ExecStart={old} --config /srv/taira/{role}/current/config/beacon.toml --sora"
            );
            let changed = raw.replace(&old, &candidate);
            units.push(norito::json!({"role":(role.clone()),"before":(base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())),
                "before_sha256":(digest(raw.as_bytes())),"after":(base64::engine::general_purpose::STANDARD.encode(changed.as_bytes())),
                "after_sha256":(digest(changed.as_bytes()))}));
            let row = norito::json!({"role":(role.clone()), "config_stamp":[1,2,3],"state_root_identity":[1,2],"current_target":"retained",
                "public":{"commit":SOURCE,"network_id":(network.to_string()),"height":12},
                "systemd":{"MainPID":"123","InvocationID":"actual","NRestarts":"0"}});
            before.push(row.clone());
            after.push(row);
            stopped.push(norito::json!({"role":(role.clone()),"cohort_stopped":true,"checkpoint_height":12,"kura_tip":{"height":12,"hash":(hex::encode(Hash::new(b"retained fixture block").as_ref()))}}));
            restored.push(norito::json!({"role":role,"native_strict_checkpoint_verified":true,"restored_height":12}));
        }
        let artifacts: Vec<_> = ["iroha3d_taira", "iroha", "kagami"]
            .into_iter()
            .map(|name| norito::json!({"name":name,"sha256":("a".repeat(64)),"size":2_000_000}))
            .collect();
        let intent = norito::json!({"schema":"taira.daemon-update.plan.v2","operation":(operation.clone()),"commit":SOURCE,
            "network_id":(network.to_string()),"secret_contents_read":false,"transaction_submission":false,
            "python_transaction_submission":false,"units":units,"artifacts":artifacts,
            "deployment":{"runtime_root":BASE,"config_root":"/srv/taira","state_root":"/var/lib/taira",
                "network_id":(network.to_string()),"genesis_manifest":"/srv/taira/genesis-manifest.json",
                "kura_hash_journal":"storage/kura/blocks/canonical/blocks.hashes",
                "current":{"commit":PREVIOUS,"daemon":old}}});
        let result = norito::json!({"schema":"taira.daemon-update.result.v2","commit":SOURCE,"network_id":(network.to_string()),
            "runtime_update_complete":true,"state_preserved":true,"retained_native_snapshot_verified":true,
            "retained_native_state_verified":true,"historical_genesis_replay_supported":false,
            "native_recovery_modes":["native_strict_restore","native_strict_restore","native_strict_restore","native_strict_restore"],
            "cohort_processes_verified_after_final_observation":true,"all_own_retained_tips_verified_after_final_observation":true});
        (
            BTreeMap::from([
                ("intent.json".into(), intent),
                ("result.json".into(), result),
                ("retained-entry.json".into(), norito::json!(before)),
                ("after.json".into(), norito::json!(after.clone())),
                (
                    "cohort-ready.json".into(),
                    norito::json!({"observations":after}),
                ),
                ("checkpoint-stopped.json".into(), norito::json!(stopped)),
                ("checkpoint-restored.json".into(), norito::json!(restored)),
            ]),
            operation,
            network,
            trust,
        )
    }

    fn public_fixture() -> (
        json::Value,
        BTreeMap<String, Vec<u8>>,
        DeploymentTrustV1,
        DeploymentTrustV1,
        NetworkId,
    ) {
        let (records, operation, network, original) = fixture();
        let originals = records
            .iter()
            .map(|(name, value)| (name.clone(), json::to_vec(value).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let hashes = originals
            .iter()
            .map(|(name, bytes)| (name.clone(), digest(bytes)))
            .collect::<BTreeMap<_, _>>();
        let mut effective = original.clone();
        for peer in &mut effective.peers {
            peer.build_fingerprint = selected_source_fingerprint(SOURCE, VERSION).unwrap();
        }
        let receipt = norito::json!({"schema":"iroha.dataspace-runtime-update-verification.v1", "operation_directory":(format!("{BASE}/{operation}")),
            "source_commit":SOURCE,"receipt_sha256":hashes,"original_trust_sha256":(digest(&json::to_vec(&original).unwrap())),
            "effective_trust_sha256":(digest(&json::to_vec(&effective).unwrap())),"chain_write_performed":false});
        (receipt, originals, original, effective, network)
    }

    struct ChainFixture {
        receipt: json::Value,
        originals: BTreeMap<String, Vec<u8>>,
        original: DeploymentTrustV1,
        effective: DeploymentTrustV1,
        network: NetworkId,
    }

    fn put(value: &mut json::Value, key: &str, replacement: json::Value) {
        value
            .as_object_mut()
            .unwrap()
            .insert(key.into(), replacement);
    }

    impl ChainFixture {
        fn verify(&self) -> Result<json::Value> {
            verify_public_originals(
                &self.receipt,
                &self.originals,
                &self.original,
                &self.effective,
                self.network,
                text(&self.receipt, "source_commit")?,
                VERSION,
            )
        }

        /// Rehash modified DATA so refusal exercises semantic joins, not merely SHA checks.
        fn change_record(
            &mut self,
            index: usize,
            name: &str,
            change: impl FnOnce(&mut json::Value),
        ) {
            let key = chain_name(index, name);
            let mut value = json::from_slice(&self.originals[&key]).unwrap();
            change(&mut value);
            let bytes = json::to_vec(&value).unwrap();
            let step = self
                .receipt
                .get_mut("updates")
                .unwrap()
                .get_mut(index)
                .unwrap();
            put(
                step.get_mut("receipt_sha256").unwrap(),
                name,
                norito::json!(digest(&bytes)),
            );
            self.originals.insert(key, bytes);
        }
    }

    fn chain_fixture(count: usize) -> ChainFixture {
        chain_fixture_selected(count, None, None)
    }

    fn chain_fixture_selected(
        count: usize,
        terminal: Option<&str>,
        retirement: Option<usize>,
    ) -> ChainFixture {
        let (_, _, network, original) = fixture();
        let mut trust = original.clone();
        let mut updates = Vec::new();
        let mut originals = BTreeMap::new();
        let mut prior_records: Option<BTreeMap<String, json::Value>> = None;
        let mut prior_source = PREVIOUS.to_owned();
        let mut prior_operation = String::new();
        let mut prior_intent_hash = String::new();
        for index in 0..count {
            let (mut records, _, _, _) = fixture();
            let source = if index + 1 == count {
                terminal.map(str::to_owned)
            } else {
                None
            }
            .unwrap_or_else(|| format!("{:040x}", index + 2));
            let operation = format!("update-{index:032x}");
            let old_daemon = if prior_records.is_some() {
                format!("{BASE}/release-{prior_source}-{prior_operation}/bin/iroha3d_taira")
            } else {
                format!("{BASE}/previous/bin/iroha3d_taira")
            };
            let daemon = format!("{BASE}/release-{source}-{operation}/bin/iroha3d_taira");
            let plan = records.get_mut("intent.json").unwrap();
            put(plan, "commit", norito::json!(source.clone()));
            put(plan, "operation", norito::json!(operation.clone()));
            let deployment = plan.get_mut("deployment").unwrap();
            put(deployment, "config_release", norito::json!(PREVIOUS));
            put(deployment, "config_filename", norito::json!("beacon.toml"));
            put(
                deployment,
                "current",
                norito::json!({"kind":"completed-update",
                "commit":(prior_source.clone()),"daemon":(old_daemon.clone()),
                "attempt_name":(prior_operation.clone()),
                "local_plan_sha256":(prior_intent_hash.clone()),
                "plan_schema":"taira.daemon-update.plan.v2","result_schema":"taira.daemon-update.result.v2"}),
            );
            let mut units = Vec::new();
            for peer in 0..4 {
                let role = format!("taira-validator-{}", peer + 1);
                let raw = if let Some(prior) = &prior_records {
                    base64::engine::general_purpose::STANDARD
                        .decode(
                            text(
                                &rows(field(&prior["intent.json"], "units").unwrap()).unwrap()
                                    [peer],
                                "after",
                            )
                            .unwrap(),
                        )
                        .unwrap()
                } else {
                    format!("ExecStart={old_daemon} --config /srv/taira/{role}/current/config/beacon.toml --sora\n").into_bytes()
                };
                let changed = std::str::from_utf8(&raw)
                    .unwrap()
                    .replace(&old_daemon, &daemon)
                    .into_bytes();
                units.push(norito::json!({"role":role,"before":(base64::engine::general_purpose::STANDARD.encode(&raw)),
                    "before_sha256":(digest(&raw)),"after":(base64::engine::general_purpose::STANDARD.encode(&changed)),
                    "after_sha256":(digest(&changed))}));
            }
            put(plan, "units", norito::json!(units));
            let mut before = if let Some(prior) = &prior_records {
                field(&prior["cohort-ready.json"], "observations")
                    .unwrap()
                    .clone()
            } else {
                records["retained-entry.json"].clone()
            };
            for (peer, row) in before.as_array_mut().unwrap().iter_mut().enumerate() {
                put(
                    row.get_mut("public").unwrap(),
                    "commit",
                    norito::json!(prior_source.clone()),
                );
                if prior_records.is_none() {
                    put(
                        row,
                        "config_stamp",
                        norito::json!([1, (10 + peer), 33152, 0, 0, 1, 100, 1000, 1000]),
                    );
                }
            }
            let mut after = before.clone();
            for row in after.as_array_mut().unwrap() {
                put(
                    row.get_mut("public").unwrap(),
                    "commit",
                    norito::json!(source.clone()),
                );
            }
            records.insert("retained-entry.json".into(), before);
            records.insert("after.json".into(), after.clone());
            records.insert(
                "cohort-ready.json".into(),
                norito::json!({"observations":after}),
            );
            put(
                records.get_mut("result.json").unwrap(),
                "commit",
                norito::json!(source.clone()),
            );
            if retirement == Some(index) {
                add_retirement(&mut records, &operation, network, &source);
            }
            validate_records(&records, &operation, network, &source, &trust, VERSION).unwrap();
            let mut hashes = BTreeMap::new();
            for (name, value) in &records {
                let bytes = json::to_vec(value).unwrap();
                hashes.insert(name.clone(), digest(&bytes));
                originals.insert(chain_name(index, name), bytes);
            }
            let original_hash = digest(&json::to_vec(&trust).unwrap());
            for peer in &mut trust.peers {
                peer.build_fingerprint = selected_source_fingerprint(&source, VERSION).unwrap();
            }
            updates.push(norito::json!({"schema":"iroha.dataspace-runtime-update-verification.v1",
                "operation_directory":(format!("{BASE}/{operation}")),"source_commit":(source.clone()),
                "receipt_sha256":(hashes.clone()),"original_trust_sha256":original_hash,
                "effective_trust_sha256":(digest(&json::to_vec(&trust).unwrap())),"chain_write_performed":false}));
            prior_records = Some(records);
            prior_source = source;
            prior_operation = operation;
            prior_intent_hash = hashes["intent.json"].clone();
        }
        ChainFixture {
            receipt: norito::json!({"schema":CHAIN_SCHEMA,"source_commit":prior_source,
            "original_trust_sha256":(digest(&json::to_vec(&original).unwrap())),
            "effective_trust_sha256":(digest(&json::to_vec(&trust).unwrap())),"updates":updates,"chain_write_performed":false}),
            originals,
            original,
            effective: trust,
            network,
        }
    }

    #[test]
    fn portable_runtime_chain_replays_two_and_maximum_hops_without_host_authority() {
        for count in [2, MAX_UPDATES] {
            let fixture = chain_fixture(count);
            let result = fixture.verify().unwrap();
            assert_eq!(result["host_custody_verified"].as_bool(), Some(false));
            assert_eq!(result["semantic_joins_verified"].as_bool(), Some(true));
            assert_eq!(rows(&result["updates"]).unwrap().len(), count);
            assert_eq!(
                portable_record_names(&fixture.receipt).unwrap().len(),
                count * RECORDS.len()
            );
            assert!(fixture.originals.contains_key("chain-0000-intent.json"));
            assert_eq!(
                fixture.original.peers[0].build_fingerprint,
                selected_source_fingerprint(PREVIOUS, VERSION).unwrap()
            );
        }
    }

    #[test]
    fn portable_runtime_chain_replays_historical_or_terminal_retirement_and_refuses_source_cycles()
    {
        for retired in [0, 1] {
            let fixture = chain_fixture_selected(2, None, Some(retired));
            fixture.verify().unwrap();
            assert_eq!(portable_record_names(&fixture.receipt).unwrap().len(), 16);
            assert!(
                fixture
                    .originals
                    .contains_key(&chain_name(retired, "config-retirement-installed.json"))
            );
        }
        // Both constituent transitions are individually valid; returning to the
        // allocation's original build still cannot become a chain authority.
        let fixture = chain_fixture_selected(2, Some(PREVIOUS), None);
        assert!(
            fixture
                .verify()
                .unwrap_err()
                .to_string()
                .contains("source cycle")
        );
    }

    #[test]
    fn runtime_chain_config_filename_is_closed_and_preserves_the_existing_default() {
        assert_eq!(config_filename(&norito::json!({})).unwrap(), "config.toml");
        for filename in ["config.toml", "beacon.toml"] {
            assert_eq!(
                config_filename(&norito::json!({"config_filename":filename})).unwrap(),
                filename
            );
        }
        for value in [
            norito::json!(null),
            norito::json!(7),
            norito::json!("../config.toml"),
        ] {
            assert!(config_filename(&norito::json!({"config_filename":value})).is_err());
        }
    }

    #[test]
    fn portable_runtime_chain_rejects_omitted_reordered_duplicate_nested_and_excess_hops() {
        for mutation in 0..6 {
            let mut fixture = chain_fixture(2);
            let replacement = fixture.receipt.clone();
            let steps = fixture
                .receipt
                .get_mut("updates")
                .unwrap()
                .as_array_mut()
                .unwrap();
            match mutation {
                0 => {
                    steps.remove(0);
                }
                1 => steps.reverse(),
                2 => steps[1] = steps[0].clone(),
                3 => steps[0] = replacement,
                4 => steps.clear(),
                _ => {
                    let step = steps[0].clone();
                    steps.resize(MAX_UPDATES + 1, step);
                }
            }
            assert!(fixture.verify().is_err(), "mutation {mutation}");
        }
        let mut fixture = chain_fixture(2);
        put(&mut fixture.receipt, "unreviewed", norito::json!(true));
        assert!(fixture.verify().is_err());
    }

    #[test]
    fn portable_runtime_chain_requires_exact_originals_and_each_trust_link() {
        for index in 0..2 {
            for name in RECORDS {
                let mut fixture = chain_fixture(2);
                fixture.originals.remove(&chain_name(index, name));
                assert!(fixture.verify().is_err());
                let mut fixture = chain_fixture(2);
                fixture
                    .originals
                    .get_mut(&chain_name(index, name))
                    .unwrap()
                    .push(b' ');
                assert!(fixture.verify().is_err());
            }
            for key in [
                "original_trust_sha256",
                "effective_trust_sha256",
                "source_commit",
            ] {
                let mut fixture = chain_fixture(2);
                let step = fixture
                    .receipt
                    .get_mut("updates")
                    .unwrap()
                    .get_mut(index)
                    .unwrap();
                put(
                    step,
                    key,
                    norito::json!("f".repeat(if key == "source_commit" { 40 } else { 64 })),
                );
                assert!(fixture.verify().is_err(), "{index} {key}");
            }
            for name in [
                "config-retirement-prepared.json",
                "config-retirement-installed.json",
            ] {
                let mut fixture = chain_fixture(2);
                let step = fixture
                    .receipt
                    .get_mut("updates")
                    .unwrap()
                    .get_mut(index)
                    .unwrap();
                put(
                    step.get_mut("receipt_sha256").unwrap(),
                    name,
                    norito::json!("a".repeat(64)),
                );
                assert!(fixture.verify().is_err());
            }
        }
        let mut fixture = chain_fixture(2);
        fixture
            .originals
            .insert("unexpected.json".into(), b"{}".to_vec());
        assert!(fixture.verify().is_err());
        let mut fixture = chain_fixture(2);
        fixture.effective.peers[0].config_fingerprint = Hash::new(b"substituted authority");
        put(
            &mut fixture.receipt,
            "effective_trust_sha256",
            norito::json!(digest(&json::to_vec(&fixture.effective).unwrap())),
        );
        assert!(fixture.verify().is_err());
    }

    #[test]
    fn portable_runtime_chain_requires_exact_predecessor_and_retained_installation() {
        for key in [
            "kind",
            "commit",
            "attempt_name",
            "daemon",
            "local_plan_sha256",
            "plan_schema",
            "result_schema",
        ] {
            let mut fixture = chain_fixture(2);
            fixture.change_record(1, "intent.json", |record| {
                put(
                    record
                        .get_mut("deployment")
                        .unwrap()
                        .get_mut("current")
                        .unwrap(),
                    key,
                    norito::json!("changed"),
                )
            });
            assert!(fixture.verify().is_err(), "{key}");
        }
        for key in [
            "runtime_root",
            "config_root",
            "state_root",
            "config_release",
            "config_filename",
            "genesis_manifest",
            "kura_hash_journal",
        ] {
            let mut fixture = chain_fixture(2);
            fixture.change_record(1, "intent.json", |record| {
                put(
                    record.get_mut("deployment").unwrap(),
                    key,
                    norito::json!("changed"),
                )
            });
            assert!(fixture.verify().is_err(), "{key}");
        }
        for key in [
            "role",
            "state_root_identity",
            "current_target",
            "config_stamp",
        ] {
            let mut fixture = chain_fixture(2);
            fixture.change_record(1, "retained-entry.json", |record| {
                put(
                    record.get_mut(0usize).unwrap(),
                    key,
                    norito::json!("changed"),
                )
            });
            assert!(fixture.verify().is_err(), "{key}");
        }
        for (key, value) in [
            ("height", norito::json!(1)),
            ("commit", norito::json!(PREVIOUS)),
            ("network_id", norito::json!("wrong")),
        ] {
            let mut fixture = chain_fixture(2);
            fixture.change_record(1, "retained-entry.json", |record| {
                put(
                    record.get_mut(0usize).unwrap().get_mut("public").unwrap(),
                    key,
                    value,
                )
            });
            assert!(fixture.verify().is_err(), "{key}");
        }
    }

    pub(super) fn chain_retained_tip_claims(height: u64, hash: Hash) -> Result<RetainedTips> {
        let mut fixture = chain_fixture(2);
        for index in 0..2 {
            fixture.change_record(index, "checkpoint-stopped.json", |record| {
                for row in record.as_array_mut().unwrap() {
                    put(row, "checkpoint_height", norito::json!(height));
                    put(
                        row,
                        "kura_tip",
                        norito::json!({"height":height,"hash":(hex::encode(hash.as_ref()))}),
                    );
                }
            });
            fixture.change_record(index, "checkpoint-restored.json", |record| {
                for row in record.as_array_mut().unwrap() {
                    put(row, "restored_height", norito::json!(height));
                }
            });
            for name in ["retained-entry.json", "after.json", "cohort-ready.json"] {
                fixture.change_record(index, name, |record| {
                    let rows = if name == "cohort-ready.json" {
                        record.get_mut("observations").unwrap()
                    } else {
                        record
                    };
                    for row in rows.as_array_mut().unwrap() {
                        put(
                            row.get_mut("public").unwrap(),
                            "height",
                            norito::json!(height),
                        );
                    }
                });
            }
        }
        // Every changed receipt is consistently rehashed; proof mismatch must be
        // caught by the authenticated prefix, never by a superficial digest check.
        fixture.verify()?;
        retained_tip_claims(&fixture.receipt, &fixture.originals)
    }

    #[test]
    fn portable_runtime_chain_rejects_rehashed_missing_changed_and_decreasing_tips() {
        for mutation in 0..5 {
            let mut fixture = chain_fixture(3);
            fixture.change_record(1, "checkpoint-stopped.json", |record| {
                let tip = record.get_mut(0usize).unwrap().get_mut("kura_tip").unwrap();
                match mutation {
                    0 => {
                        tip.as_object_mut().unwrap().remove("hash");
                    }
                    1 => put(
                        tip,
                        "hash",
                        norito::json!(hex::encode(Hash::new(b"different middle block").as_ref())),
                    ),
                    2 => put(tip, "height", norito::json!(11)),
                    3 => put(tip, "height", norito::json!(0)),
                    _ => put(tip, "hash", norito::json!("0".repeat(64))),
                }
            });
            assert!(
                fixture.verify().is_err(),
                "rehashed tip mutation {mutation}"
            );
        }
        // A source-native replay claim must retain the same exact checkpoint hash.
        let (mut records, operation, network, trust) = fixture();
        records
            .get_mut("checkpoint-stopped.json")
            .unwrap()
            .get_mut(0usize)
            .unwrap()
            .get_mut("kura_tip")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("hash");
        assert!(validate_records(&records, &operation, network, SOURCE, &trust, VERSION).is_err());
    }

    #[test]
    fn portable_runtime_chain_preserves_all_deployment_metadata_and_tip_inventory() {
        for key in [
            "genesis_manifest",
            "kura_hash_journal",
            "public_origin",
            "renderer_sha256",
        ] {
            let mut fixture = chain_fixture(2);
            fixture.change_record(1, "intent.json", |record| {
                put(
                    record.get_mut("deployment").unwrap(),
                    key,
                    norito::json!("changed"),
                );
            });
            assert!(
                fixture
                    .verify()
                    .unwrap_err()
                    .to_string()
                    .contains("retained deployment"),
                "{key}"
            );
        }
        let fixture = chain_fixture(2);
        fixture.verify().unwrap();
        let claims = retained_tip_claims(&fixture.receipt, &fixture.originals).unwrap();
        assert_eq!(claims.heights().collect::<Vec<_>>(), vec![12]);
        let mut originals = fixture.originals.clone();
        originals.remove(&chain_name(0, "checkpoint-stopped.json"));
        assert!(retained_tip_claims(&fixture.receipt, &originals).is_err());
    }

    #[test]
    fn runtime_chain_selection_is_direct_bounded_and_read_only_off_linux() {
        let paths = (0..MAX_UPDATES)
            .map(|index| PathBuf::from(format!("{BASE}/update-{index:032x}")))
            .collect::<Vec<_>>();
        validate_selection(&paths).unwrap();
        for invalid in [
            format!("{BASE}/update-{}", "A".repeat(32)),
            format!("{BASE}/./update-{}", "a".repeat(32)),
            format!("{BASE}/update-{}/", "a".repeat(32)),
            "relative/update-00000000000000000000000000000000".into(),
        ] {
            assert!(validate_selection(&[PathBuf::from(invalid)]).is_err());
        }
        assert!(validate_selection(&[paths[0].clone(), paths[0].clone()]).is_err());
        let mut excessive = paths.clone();
        excessive.push(PathBuf::from(format!("{BASE}/update-{}", "f".repeat(32))));
        assert!(validate_selection(&excessive).is_err());
        let (_, _, network, trust) = fixture();
        assert!(Verified::admit_chain(&[], &trust, network, Some((SOURCE, VERSION))).is_err());
        #[cfg(not(target_os = "linux"))]
        {
            assert!(
                Verified::admit_chain(&paths[..2], &trust, network, Some((SOURCE, VERSION)))
                    .is_err()
            );
            assert!(Verified::admit_chain(&paths[..2], &trust, network, None).is_err());
        }
    }

    #[test]
    fn portable_runtime_chain_rejects_individually_valid_but_disjoint_units_and_state() {
        let mut fixture = chain_fixture(2);
        fixture.change_record(1, "intent.json", |record| {
            let unit = record.get_mut("units").unwrap().get_mut(0usize).unwrap();
            for side in ["before", "after"] {
                let mut bytes = base64::engine::general_purpose::STANDARD
                    .decode(text(unit, side).unwrap())
                    .unwrap();
                bytes.extend_from_slice(b"# changed between updates\n");
                put(
                    unit,
                    side,
                    norito::json!(base64::engine::general_purpose::STANDARD.encode(&bytes)),
                );
                put(
                    unit,
                    &format!("{side}_sha256"),
                    norito::json!(digest(&bytes)),
                );
            }
        });
        assert!(
            fixture
                .verify()
                .unwrap_err()
                .to_string()
                .contains("units are not adjacent")
        );
        for (key, value) in [
            ("state_root_identity", norito::json!([99, 99])),
            ("current_target", norito::json!("changed")),
            ("config_stamp", norito::json!([99, 99, 99])),
        ] {
            let mut fixture = chain_fixture(2);
            for name in ["retained-entry.json", "after.json", "cohort-ready.json"] {
                fixture.change_record(1, name, |record| {
                    let rows = if name == "cohort-ready.json" {
                        record.get_mut("observations").unwrap()
                    } else {
                        record
                    };
                    put(rows.get_mut(0usize).unwrap(), key, value.clone());
                });
            }
            assert!(
                fixture
                    .verify()
                    .unwrap_err()
                    .to_string()
                    .contains("changed retained peer custody"),
                "{key}"
            );
        }
    }

    #[test]
    fn portable_runtime_public_joins_preserve_authority_scope_and_exact_source() {
        let (receipt, originals, original, effective, network) = public_fixture();
        let result = verify_public_originals(
            &receipt, &originals, &original, &effective, network, SOURCE, VERSION,
        )
        .unwrap();
        assert_eq!(result["semantic_joins_verified"].as_bool(), Some(true));
        assert_eq!(result["host_custody_verified"].as_bool(), Some(false));
        let compiled = iroha_core::release_identity::BuildIdentity::from_compiled_parts(
            VERSION,
            Some(SOURCE),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            selected_source_fingerprint(SOURCE, VERSION).unwrap(),
            compiled.build_fingerprint()
        );
        assert!(
            verify_public_originals(
                &receipt, &originals, &original, &effective, network, PREVIOUS, VERSION
            )
            .is_err()
        );
        assert!(
            verify_public_originals(
                &receipt,
                &originals,
                &original,
                &effective,
                network,
                SOURCE,
                "another-version"
            )
            .is_err()
        );
        let mut changed = effective.clone();
        changed.peers[0].config_fingerprint = Hash::new(b"substituted config");
        assert!(
            verify_public_originals(
                &receipt, &originals, &original, &changed, network, SOURCE, VERSION
            )
            .is_err()
        );
    }

    #[test]
    fn portable_runtime_requires_whole_originals_and_paired_retirement_metadata() {
        let (receipt, originals, original, effective, network) = public_fixture();
        for name in RECORDS {
            let mut missing = originals.clone();
            missing.remove(name);
            assert!(
                verify_public_originals(
                    &receipt, &missing, &original, &effective, network, SOURCE, VERSION
                )
                .is_err()
            );
            let mut changed = originals.clone();
            changed.get_mut(name).unwrap().push(b' ');
            assert!(
                verify_public_originals(
                    &receipt, &changed, &original, &effective, network, SOURCE, VERSION
                )
                .is_err()
            );
        }
        for single in [
            "config-retirement-prepared.json",
            "config-retirement-installed.json",
        ] {
            let mut changed = receipt.clone();
            changed
                .get_mut("receipt_sha256")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(single.into(), norito::json!("a".repeat(64)));
            assert!(portable_record_names(&changed).is_err());
        }
        let mut changed = receipt.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert("host_verified".into(), norito::json!(true));
        assert!(portable_record_names(&changed).is_err());
    }

    fn add_retirement(
        records: &mut BTreeMap<String, json::Value>,
        operation: &str,
        network: NetworkId,
        source: &str,
    ) {
        let deployment = records
            .get_mut("intent.json")
            .unwrap()
            .get_mut("deployment")
            .unwrap()
            .as_object_mut()
            .unwrap();
        deployment.insert("config_release".into(), norito::json!(PREVIOUS));
        deployment.insert("config_filename".into(), norito::json!("beacon.toml"));
        let mut prepared_rows = Vec::new();
        let mut installed_rows = Vec::new();
        for index in 0..4 {
            let role = format!("taira-validator-{}", index + 1);
            let source = format!("/srv/taira/{role}/releases/{PREVIOUS}/config/beacon.toml");
            let sibling =
                format!("/srv/taira/{role}/releases/{PREVIOUS}/config/.beacon.toml.{operation}");
            let before = norito::json!([1, (10 + index), 33152, 0, 0, 1, 100, 1000, 1000]);
            let staged = norito::json!([1, (20 + index), 33152, 0, 0, 1, 90, 2000, 2000]);
            let installed = norito::json!([1, (20 + index), 33152, 0, 0, 1, 90, 2000, 3000]);
            let row = norito::json!({"role":role,"source_path":source,"staged_path":(format!("{sibling}.retirement-next")),"original_path":(format!("{sibling}.retirement-original")),"changed":true,"source_sha256":("d".repeat(64)),"output_sha256":("e".repeat(64)),"before_stamp":(before.clone()),"staged_stamp":staged});
            let mut final_row = row.clone();
            final_row
                .as_object_mut()
                .unwrap()
                .insert("installed_stamp".into(), installed.clone());
            prepared_rows.push(row);
            installed_rows.push(final_row);
            *records
                .get_mut("retained-entry.json")
                .unwrap()
                .get_mut(index)
                .unwrap()
                .get_mut("config_stamp")
                .unwrap() = before;
            *records
                .get_mut("after.json")
                .unwrap()
                .get_mut(index)
                .unwrap()
                .get_mut("config_stamp")
                .unwrap() = installed.clone();
            *records
                .get_mut("cohort-ready.json")
                .unwrap()
                .get_mut("observations")
                .unwrap()
                .get_mut(index)
                .unwrap()
                .get_mut("config_stamp")
                .unwrap() = installed;
        }
        for (kind, rows) in [("prepared", prepared_rows), ("installed", installed_rows)] {
            records.insert(format!("config-retirement-{kind}.json"), norito::json!({"schema":(format!("taira.validator-config-retirement.{kind}.v1")),"operation":(operation.clone()),"source_commit":source,"network_id":(network.to_string()),"rows":rows}));
        }
    }

    #[test]
    fn runtime_transition_accepts_only_the_native_config_stamp_join() {
        let (mut records, operation, network, trust) = fixture();
        add_retirement(&mut records, &operation, network, SOURCE);
        validate_records(&records, &operation, network, SOURCE, &trust, VERSION).unwrap();
        let mut changed = records.clone();
        *changed
            .get_mut("after.json")
            .unwrap()
            .get_mut(0usize)
            .unwrap()
            .get_mut("config_stamp")
            .unwrap()
            .get_mut(1usize)
            .unwrap() = norito::json!(999);
        assert!(validate_records(&changed, &operation, network, SOURCE, &trust, VERSION).is_err());
        records.remove("config-retirement-prepared.json");
        records.remove("config-retirement-installed.json");
        assert!(validate_records(&records, &operation, network, SOURCE, &trust, VERSION).is_err());
    }

    #[test]
    fn runtime_transition_requires_complete_native_retirement_evidence() {
        let (mut records, operation, network, trust) = fixture();
        records.insert("config-retirement-prepared.json".into(), norito::json!({}));
        assert!(validate_records(&records, &operation, network, SOURCE, &trust, VERSION).is_err());
        records.remove("config-retirement-prepared.json");
        records.insert("config-retirement-installed.json".into(), norito::json!({}));
        assert!(validate_records(&records, &operation, network, SOURCE, &trust, VERSION).is_err());
    }

    #[test]
    fn runtime_transition_joins_truthful_replay_cohort_completion() {
        let (mut records, operation, network, trust) = fixture();
        let events = norito::json!([
            {"time_us":1,"message":"Failed to load state snapshot error=NativeExecutionReplayRequired"},
            {"time_us":2,"message":"Kura retains the configured-primary replay floor; rebuilding state from blocks"},
            {"time_us":3,"message":"Sumeragi rebuilt the state from genesis and Kura height=12"}
        ]);
        for index in 0..4 {
            let stopped = rows(&records["checkpoint-stopped.json"]).unwrap()[index].clone();
            let recovered = records
                .get_mut("checkpoint-restored.json")
                .unwrap()
                .get_mut(index)
                .unwrap()
                .as_object_mut()
                .unwrap();
            recovered.insert(
                "native_strict_checkpoint_verified".into(),
                norito::json!(false),
            );
            recovered.insert(
                "native_authenticated_kura_replay_verified".into(),
                norito::json!(true),
            );
            recovered.insert(
                "proof_kind".into(),
                norito::json!("native_authenticated_kura_replay"),
            );
            recovered.insert("source_commit".into(), norito::json!(SOURCE));
            recovered.insert("network_id".into(), norito::json!(network.to_string()));
            recovered.insert(
                "retained_kura_tip".into(),
                field(&stopped, "kura_tip").unwrap().clone(),
            );
            recovered.insert("events".into(), events.clone());
            records
                .get_mut("after.json")
                .unwrap()
                .get_mut(index)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(
                    "cohort_observation".into(),
                    norito::json!({"ready":true,"public_fresh":true}),
                );
            records
                .get_mut("cohort-ready.json")
                .unwrap()
                .get_mut("observations")
                .unwrap()
                .get_mut(index)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(
                    "cohort_observation".into(),
                    norito::json!({"ready":true,"public_fresh":true}),
                );
        }
        let result = records
            .get_mut("result.json")
            .unwrap()
            .as_object_mut()
            .unwrap();
        result.insert(
            "retained_native_snapshot_verified".into(),
            norito::json!(false),
        );
        result.insert("retained_native_state_verified".into(), norito::json!(true));
        result.insert(
            "historical_genesis_replay_supported".into(),
            norito::json!(true),
        );
        result.insert(
            "native_recovery_modes".into(),
            json::to_value(&vec!["native_authenticated_kura_replay"; 4]).unwrap(),
        );
        validate_records(&records, &operation, network, SOURCE, &trust, VERSION).unwrap();
        for (name, value) in [
            ("retained_native_snapshot_verified", norito::json!(true)),
            ("retained_native_state_verified", norito::json!(false)),
            ("historical_genesis_replay_supported", norito::json!(false)),
            (
                "native_recovery_modes",
                norito::json!(["native_strict_restore"]),
            ),
        ] {
            let mut bad = records.clone();
            bad.get_mut("result.json")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(name.into(), value);
            assert!(validate_records(&bad, &operation, network, SOURCE, &trust, VERSION).is_err());
        }
    }

    #[test]
    fn runtime_transition_native_replay_requires_exact_policy_prefix_and_ready_identity() {
        let (_, _, network, _) = fixture();
        let events = norito::json!([
            {"time_us":1,"message":"Failed to load state snapshot; checking whether Kura can rebuild from an empty state error=NativeExecutionReplayRequired"},
            {"time_us":2,"message":"Kura retains the configured-primary replay floor; rebuilding state from blocks"},
            {"time_us":3,"message":"Sumeragi rebuilt the state from genesis and Kura height=12 instance=abc"}
        ]);
        let tip = norito::json!({"height":12,"hash":("a".repeat(64))});
        let stopped = norito::json!({"checkpoint_height":12,"kura_tip":(tip.clone())});
        let after = norito::json!({"public":{"height":12},"cohort_observation":{"ready":true,"public_fresh":true}});
        let restored = norito::json!({"native_strict_checkpoint_verified":false,
            "native_authenticated_kura_replay_verified":true,"proof_kind":"native_authenticated_kura_replay",
            "source_commit":SOURCE,"network_id":(network.to_string()),"retained_kura_tip":tip,
            "restored_height":12,"events":events});
        assert!(
            !verify_restored_record(&restored, &stopped, &after, SOURCE, network, true).unwrap()
        );
        assert!(
            verify_restored_record(&restored, &stopped, &after, SOURCE, network, false).is_err()
        );
        for (name, value) in [
            ("native_strict_checkpoint_verified", norito::json!(true)),
            ("source_commit", norito::json!(PREVIOUS)),
            ("network_id", norito::json!("foreign")),
            (
                "retained_kura_tip",
                norito::json!({"height":12,"hash":("b".repeat(64))}),
            ),
            ("restored_height", norito::json!(11)),
            (
                "native_authenticated_kura_replay_verified",
                norito::json!(false),
            ),
        ] {
            let mut bad = restored.clone();
            bad.as_object_mut().unwrap().insert(name.into(), value);
            assert!(verify_restored_record(&bad, &stopped, &after, SOURCE, network, true).is_err());
        }
        let events = field(&restored, "events").unwrap();
        for (index, name, value) in [
            (
                0usize,
                "message",
                norito::json!("Failed to load state snapshot error=NotFound"),
            ),
            (1usize, "time_us", norito::json!(4)),
            (
                2usize,
                "message",
                norito::json!("Sumeragi rebuilt the state from genesis and Kura height=0"),
            ),
            (2usize, "message", norito::json!("emergency Fast")),
        ] {
            let mut bad = events.clone();
            bad.get_mut(index)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(name.into(), value);
            assert!(authenticated_replay_height(&bad).is_err());
        }
        for suffix in [
            "height=12 height=12",
            "height=12 height=bad",
            "height=12,",
            "height=+12",
            "height=",
            "height=１２",
            "",
        ] {
            let mut bad = events.clone();
            bad.get_mut(2).unwrap().as_object_mut().unwrap().insert(
                "message".into(),
                norito::json!(format!(
                    "Sumeragi rebuilt the state from genesis and Kura {suffix}"
                )),
            );
            assert!(authenticated_replay_height(&bad).is_err());
        }
        for key in ["ready", "public_fresh"] {
            let mut bad = after.clone();
            bad.get_mut("cohort_observation")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), norito::json!(false));
            assert!(
                verify_restored_record(&restored, &stopped, &bad, SOURCE, network, true).is_err()
            );
        }
    }

    #[test]
    fn runtime_transition_strict_completion_rejects_contradictory_mode_flags() {
        let (records, operation, network, trust) = fixture();
        validate_records(&records, &operation, network, SOURCE, &trust, VERSION).unwrap();
        for (key, value) in [
            ("retained_native_state_verified", norito::json!(false)),
            ("historical_genesis_replay_supported", norito::json!(true)),
            (
                "native_recovery_modes",
                json::to_value(&vec!["native_authenticated_kura_replay"; 4]).unwrap(),
            ),
        ] {
            let mut bad = records.clone();
            bad.get_mut("result.json")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), value);
            assert!(validate_records(&bad, &operation, network, SOURCE, &trust, VERSION).is_err());
        }
    }

    #[test]
    fn runtime_transition_requires_completed_exact_source_and_preserved_native_cohort() {
        let (records, operation, network, trust) = fixture();
        validate_records(&records, &operation, network, SOURCE, &trust, VERSION).unwrap();
        for (record, field_name, value) in [
            (
                "result.json",
                "runtime_update_complete",
                norito::json!(false),
            ),
            ("result.json", "state_preserved", norito::json!(false)),
            (
                "result.json",
                "retained_native_snapshot_verified",
                norito::json!(false),
            ),
            ("result.json", "commit", norito::json!(PREVIOUS)),
            ("intent.json", "commit", norito::json!(PREVIOUS)),
            ("result.json", "network_id", norito::json!("foreign")),
            ("intent.json", "network_id", norito::json!("foreign")),
            ("intent.json", "transaction_submission", norito::json!(true)),
        ] {
            let mut changed = records.clone();
            changed
                .get_mut(record)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field_name.into(), value);
            assert!(
                validate_records(&changed, &operation, network, SOURCE, &trust, VERSION).is_err(),
                "{record}/{field_name}"
            );
        }
        let mut changed = trust.clone();
        changed.peers[0].build_fingerprint = Hash::new("foreign");
        assert!(
            validate_records(&records, &operation, network, SOURCE, &changed, VERSION).is_err()
        );
    }

    #[test]
    fn runtime_transition_rejects_rewritten_units_config_and_process_history() {
        let (records, operation, network, trust) = fixture();
        for (record, parent, name, value) in [
            ("after.json", None, "config_stamp", norito::json!([9, 9, 9])),
            (
                "checkpoint-restored.json",
                None,
                "native_strict_checkpoint_verified",
                norito::json!(false),
            ),
            (
                "checkpoint-restored.json",
                None,
                "restored_height",
                norito::json!(11),
            ),
            (
                "after.json",
                Some("systemd"),
                "MainPID",
                norito::json!("999"),
            ),
            ("after.json", Some("public"), "height", norito::json!(11)),
        ] {
            let mut changed = records.clone();
            let row = changed.get_mut(record).unwrap().get_mut(0usize).unwrap();
            let target = if let Some(parent) = parent {
                row.get_mut(parent).unwrap()
            } else {
                row
            };
            target.as_object_mut().unwrap().insert(name.into(), value);
            assert!(
                validate_records(&changed, &operation, network, SOURCE, &trust, VERSION).is_err(),
                "{record}/{name}"
            );
        }
        let mut changed = records.clone();
        let unit = changed
            .get_mut("intent.json")
            .unwrap()
            .get_mut("units")
            .unwrap()
            .get_mut(0usize)
            .unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(text(unit, "after").unwrap())
            .unwrap();
        let altered = [raw, b" --unsafe-option".to_vec()].concat();
        *unit.get_mut("after").unwrap() =
            norito::json!(base64::engine::general_purpose::STANDARD.encode(&altered));
        *unit.get_mut("after_sha256").unwrap() = norito::json!(digest(&altered));
        assert!(validate_records(&changed, &operation, network, SOURCE, &trust, VERSION).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_transition_metadata_is_nine_unsigned_json_fields() {
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public-receipt.json");
        fs::write(&path, b"{}\n").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let value = metadata_value(&metadata).unwrap();
        let fields = value.as_array().unwrap();
        assert_eq!(fields.len(), 9);
        assert!(fields.iter().all(|value| value.as_u64().is_some()));
        assert_eq!(fields[0].as_u64(), Some(metadata.dev()));
        assert_eq!(fields[1].as_u64(), Some(metadata.ino()));
        assert_eq!(fields[2].as_u64(), Some(u64::from(metadata.mode())));
        assert_eq!(fields[6].as_u64(), Some(3));
        let encoded = json::to_vec(&value).unwrap();
        assert_eq!(json::from_slice::<json::Value>(&encoded).unwrap(), value);
    }

    #[test]
    fn runtime_transition_checks_actual_artifact_and_live_process() {
        let artifact = norito::json!({"sha256":("a".repeat(64)),"size":2_000_000});
        verify_artifact(&artifact, &"a".repeat(64), 2_000_000).unwrap();
        assert!(verify_artifact(&artifact, &"b".repeat(64), 2_000_000).is_err());
        assert!(verify_artifact(&artifact, &"a".repeat(64), 2_000_001).is_err());
        let path = Path::new("/etc/systemd/system/iroha3d-taira-validator-1.service");
        let observed = BTreeMap::from(
            [
                ("LoadState", "loaded"),
                ("ActiveState", "active"),
                ("SubState", "running"),
                ("ControlPID", "0"),
                ("DropInPaths", ""),
                ("NeedDaemonReload", "no"),
                ("Job", ""),
                ("MainPID", "123"),
                ("InvocationID", "actual"),
                ("NRestarts", "0"),
                ("FragmentPath", path.to_str().unwrap()),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned())),
        );
        let expected = norito::json!({"MainPID":"123","InvocationID":"actual","NRestarts":"0"});
        verify_process(&observed, &expected, path).unwrap();
        for (key, value) in [
            ("MainPID", "999"),
            ("InvocationID", "changed"),
            ("NRestarts", "1"),
            ("NeedDaemonReload", "yes"),
            ("ActiveState", "failed"),
            ("DropInPaths", "/unapproved.conf"),
        ] {
            let mut changed = observed.clone();
            changed.insert(key.into(), value.into());
            assert!(verify_process(&changed, &expected, path).is_err(), "{key}");
        }
    }
}
