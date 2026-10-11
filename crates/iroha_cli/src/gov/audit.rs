//! Audit commands for governance workflows.
use super::shared::{
    canonicalize_hex32, compute_proposal_id, decode_hex32, print_with_summary,
    resolve_contract_address_target,
};
use crate::{Run, RunContext};
use eyre::{Result, eyre};
use iroha::client::Client;
use iroha::data_model::{
    account::AccountId,
    smart_contract::{MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1, contract_code_hash},
};
use norito::json::{Map, Value};
#[derive(clap::Args, Debug)]
pub struct AuditDeployArgs {
    #[arg(long, conflicts_with = "contract_alias")]
    pub contract_address: Option<String>,
    #[arg(long, conflicts_with = "contract_address")]
    pub contract_alias: Option<String>,
}
impl Run for AuditDeployArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let contract_address = resolve_contract_address_target(
            &client,
            self.contract_address.as_deref(),
            self.contract_alias.as_deref(),
        )?;
        let report = self.audit_contract(&client, &contract_address)?;
        let found = report
            .get("found")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let has_issues = report
            .get("has_issues")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let issue_count = report
            .get("issue_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let lifecycle = report.get("lifecycle").and_then(Value::as_object);
        let owner = lifecycle
            .and_then(|value| value.get("owner"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        let revision = lifecycle
            .and_then(|value| value.get("revision"))
            .and_then(Value::as_u64)
            .map_or_else(|| "none".to_owned(), |value| value.to_string());
        let emergency_hold_active = report
            .get("emergency_hold_active")
            .and_then(Value::as_bool)
            .map_or("none", |value| if value { "true" } else { "false" });
        let summary = Some(format!(
            "gov audit contract_address={} found={found} owner={owner} revision={revision} emergency_hold_active={emergency_hold_active} has_issues={has_issues} issue_count={issue_count}",
            contract_address,
        ));
        print_with_summary(context, summary, &report)
    }
}
impl AuditDeployArgs {
    fn audit_contract(
        &self,
        client: &Client,
        contract_address: &iroha::data_model::smart_contract::ContractAddress,
    ) -> Result<Value> {
        let binding = client.get_gov_contract_json(contract_address)?;
        let validated = validate_governed_contract_binding(&binding, contract_address.as_ref())?;
        let found = validated.found;
        let active = validated.active;
        let dataspace = validated.dataspace;
        let code_hash_raw = validated.code_hash_hex;
        let proposal_operator = binding
            .get("lifecycle")
            .and_then(|lifecycle| lifecycle.get("origin_account"))
            .and_then(Value::as_str)
            .map(AccountId::parse_encoded)
            .transpose()
            .map_err(|error| eyre!("invalid governed-contract origin account: {error}"))?;
        let mut record = Map::new();
        record.insert(
            "contract_address".into(),
            Value::from(contract_address.to_string()),
        );
        record.insert("found".into(), Value::from(found));
        record.insert("dataspace".into(), Value::from(dataspace));
        copy_contract_lifecycle_projection(&binding, &mut record);
        let mut manifest_map = Map::new();
        let mut proposal_map = Map::new();
        let mut code_map = Map::new();
        let mut issues = Vec::new();
        let Some(code_hash_raw) = code_hash_raw else {
            manifest_map.insert("present".into(), Value::from(false));
            proposal_map.insert("expected_id".into(), Value::Null);
            proposal_map.insert("found".into(), Value::from(false));
            code_map.insert("present".into(), Value::from(false));
            if let Some(issue) = missing_contract_artifact_issue(found, active) {
                issues.push(issue.into());
            }
            return Ok(finalize_record(
                record,
                manifest_map,
                proposal_map,
                code_map,
                issues,
            ));
        };
        record.insert("code_hash_input".into(), Value::from(code_hash_raw));
        let code_hash = match canonicalize_hex32(code_hash_raw) {
            Ok(hash) => hash,
            Err(err) => {
                manifest_map.insert("present".into(), Value::from(false));
                manifest_map.insert("error".into(), Value::from(err.to_string()));
                proposal_map.insert("expected_id".into(), Value::Null);
                proposal_map.insert("found".into(), Value::from(false));
                code_map.insert("present".into(), Value::from(false));
                code_map.insert("error".into(), Value::from("skipped: invalid code hash"));
                issues.push(format!(
                    "invalid_code_hash_hex: contract_address={contract_address} value={code_hash_raw}"
                ));
                return Ok(finalize_record(
                    record,
                    manifest_map,
                    proposal_map,
                    code_map,
                    issues,
                ));
            }
        };
        record.insert("code_hash".into(), Value::from(code_hash.clone()));
        let artifact_id = crate::contracts::contract_artifact_id(
            contract_address.dataspace_id()?.as_u64(),
            &code_hash,
        )?;
        let manifest_proposal_binding =
            audit_manifest_map(client, &artifact_id, &mut manifest_map, &mut issues);
        audit_code_map(client, &artifact_id, &mut code_map, &mut issues);
        audit_proposal_map(
            client,
            proposal_operator.as_ref(),
            contract_address,
            &code_hash,
            manifest_proposal_binding.as_ref(),
            &mut proposal_map,
            &mut issues,
        );
        Ok(finalize_record(
            record,
            manifest_map,
            proposal_map,
            code_map,
            issues,
        ))
    }
}
#[derive(Clone, Copy, Debug)]
struct ValidatedGovernedContractBinding<'a> {
    found: bool,
    active: Option<bool>,
    dataspace: &'a str,
    code_hash_hex: Option<&'a str>,
}
fn validate_governed_contract_binding<'a>(
    binding: &'a Value,
    expected_contract_address: &str,
) -> Result<ValidatedGovernedContractBinding<'a>> {
    const MISSING_FIELDS: &[&str] = &["found", "contract_address", "dataspace"];
    const INACTIVE_FIELDS: &[&str] = &[
        "found",
        "contract_address",
        "contract_subject_account",
        "dataspace",
        "active",
        "lifecycle",
        "emergency_hold_active",
    ];
    const ACTIVE_FIELDS: &[&str] = &[
        "found",
        "contract_address",
        "contract_subject_account",
        "dataspace",
        "active",
        "lifecycle",
        "emergency_hold_active",
        "code_hash_hex",
        "abi_hash_hex",
        "public_entrypoints",
    ];

    let object = binding
        .as_object()
        .ok_or_else(|| eyre!("governed contract response must be a JSON object"))?;
    let found = require_bool_field(object, "found", "governed contract response")?;
    let expected_fields = if !found {
        MISSING_FIELDS
    } else if require_bool_field(object, "active", "governed contract response")? {
        ACTIVE_FIELDS
    } else {
        INACTIVE_FIELDS
    };
    require_exact_fields(object, expected_fields, "governed contract response")?;
    let contract_address =
        require_nonempty_string_field(object, "contract_address", "governed contract response")?;
    if contract_address != expected_contract_address {
        return Err(eyre!(
            "governed contract response.contract_address mismatch: expected `{expected_contract_address}`, got `{contract_address}`"
        ));
    }
    let dataspace =
        require_nonempty_string_field(object, "dataspace", "governed contract response")?;
    if !found {
        return Ok(ValidatedGovernedContractBinding {
            found,
            active: None,
            dataspace,
            code_hash_hex: None,
        });
    }

    require_nonempty_string_field(
        object,
        "contract_subject_account",
        "governed contract response",
    )?;
    let active = require_bool_field(object, "active", "governed contract response")?;
    let emergency_hold_active = require_bool_field(
        object,
        "emergency_hold_active",
        "governed contract response",
    )?;
    let code_hash_hex = if active {
        let code_hash =
            require_canonical_hex32_field(object, "code_hash_hex", "governed contract response")?;
        require_nonzero_hex32(code_hash, "governed contract response.code_hash_hex")?;
        let abi_hash =
            require_canonical_hex32_field(object, "abi_hash_hex", "governed contract response")?;
        require_nonzero_hex32(abi_hash, "governed contract response.abi_hash_hex")?;
        validate_public_entrypoints(object)?;
        Some(code_hash)
    } else {
        None
    };
    validate_governed_contract_lifecycle(
        object
            .get("lifecycle")
            .ok_or_else(|| eyre!("governed contract response.lifecycle is required"))?,
        code_hash_hex,
        emergency_hold_active,
    )?;
    Ok(ValidatedGovernedContractBinding {
        found,
        active: Some(active),
        dataspace,
        code_hash_hex,
    })
}
fn validate_governed_contract_lifecycle(
    lifecycle: &Value,
    active_code_hash: Option<&str>,
    emergency_hold_active: bool,
) -> Result<()> {
    const FIELDS: &[&str] = &[
        "version",
        "origin",
        "origin_account",
        "origin_proposal_content_id_hex",
        "origin_governance_attempt_id_hex",
        "owner",
        "pending_owner",
        "parliament_delegated",
        "active_code_hash_hex",
        "retained_code_hash_hex",
        "revision",
        "emergency_hold",
    ];
    let object = lifecycle
        .as_object()
        .ok_or_else(|| eyre!("governed contract response.lifecycle must be an object"))?;
    require_exact_fields(object, FIELDS, "governed contract response.lifecycle")?;
    if require_u64_field(object, "version", "governed contract response.lifecycle")? != 1 {
        return Err(eyre!(
            "governed contract response.lifecycle.version must equal 1"
        ));
    }
    let origin =
        require_nonempty_string_field(object, "origin", "governed contract response.lifecycle")?;
    require_canonical_account_id_field(
        object,
        "origin_account",
        "governed contract response.lifecycle",
    )?;
    match origin {
        "direct" => {
            require_null_field(
                object,
                "origin_proposal_content_id_hex",
                "governed contract response.lifecycle",
            )?;
            require_null_field(
                object,
                "origin_governance_attempt_id_hex",
                "governed contract response.lifecycle",
            )?;
        }
        "parliament" => {
            let proposal_content_id = require_canonical_hex32_field(
                object,
                "origin_proposal_content_id_hex",
                "governed contract response.lifecycle",
            )?;
            require_nonzero_hex32(
                proposal_content_id,
                "governed contract response.lifecycle.origin_proposal_content_id_hex",
            )?;
            let governance_attempt_id = require_canonical_hex32_field(
                object,
                "origin_governance_attempt_id_hex",
                "governed contract response.lifecycle",
            )?;
            require_nonzero_hex32(
                governance_attempt_id,
                "governed contract response.lifecycle.origin_governance_attempt_id_hex",
            )?;
        }
        other => {
            return Err(eyre!(
                "governed contract response.lifecycle.origin must be `direct` or `parliament`, got `{other}`"
            ));
        }
    }
    let owner = require_contract_lifecycle_owner_field(
        object,
        "owner",
        "governed contract response.lifecycle",
    )?;
    let pending_owner = require_nullable_contract_lifecycle_owner_field(
        object,
        "pending_owner",
        "governed contract response.lifecycle",
    )?;
    if pending_owner.as_ref() == Some(&owner) {
        return Err(eyre!(
            "governed contract response.lifecycle.pending_owner must differ from owner"
        ));
    }
    let parliament_delegated = require_bool_field(
        object,
        "parliament_delegated",
        "governed contract response.lifecycle",
    )?;
    if owner == GovernedContractLifecycleOwner::Parliament && parliament_delegated {
        return Err(eyre!(
            "governed contract response.lifecycle.parliament_delegated must be false for a Parliament-owned contract"
        ));
    }
    let retained_code_hash = match object.get("retained_code_hash_hex") {
        Some(Value::Null) => None,
        _ => Some(require_canonical_hex32_field(
            object,
            "retained_code_hash_hex",
            "governed contract response.lifecycle",
        )?),
    };
    if active_code_hash.is_some() && retained_code_hash != active_code_hash {
        return Err(eyre!(
            "governed contract response.lifecycle.retained_code_hash_hex must match active_code_hash_hex for an active binding"
        ));
    }
    match active_code_hash {
        Some(expected) => {
            let actual = require_canonical_hex32_field(
                object,
                "active_code_hash_hex",
                "governed contract response.lifecycle",
            )?;
            if actual != expected {
                return Err(eyre!(
                    "governed contract response.lifecycle.active_code_hash_hex must match code_hash_hex"
                ));
            }
        }
        None => require_null_field(
            object,
            "active_code_hash_hex",
            "governed contract response.lifecycle",
        )?,
    }
    if require_u64_field(object, "revision", "governed contract response.lifecycle")? == 0 {
        return Err(eyre!(
            "governed contract response.lifecycle.revision must be non-zero"
        ));
    }
    match object.get("emergency_hold") {
        Some(Value::Null) => {
            if emergency_hold_active {
                return Err(eyre!(
                    "governed contract response.emergency_hold_active cannot be true without a retained emergency hold"
                ));
            }
        }
        Some(value) => validate_governed_contract_emergency_hold(value)?,
        None => {
            return Err(eyre!(
                "governed contract response.lifecycle.emergency_hold is required"
            ));
        }
    }
    Ok(())
}
fn validate_governed_contract_emergency_hold(hold: &Value) -> Result<()> {
    const FIELDS: &[&str] = &[
        "incident_digest_hex",
        "proposal_content_id_hex",
        "governance_attempt_id_hex",
        "reason",
        "imposed_at_height",
        "expires_at_height",
    ];
    let object = hold.as_object().ok_or_else(|| {
        eyre!("governed contract response.lifecycle.emergency_hold must be an object or null")
    })?;
    require_exact_fields(
        object,
        FIELDS,
        "governed contract response.lifecycle.emergency_hold",
    )?;
    for field in [
        "incident_digest_hex",
        "proposal_content_id_hex",
        "governance_attempt_id_hex",
    ] {
        let value = require_canonical_hex32_field(
            object,
            field,
            "governed contract response.lifecycle.emergency_hold",
        )?;
        require_nonzero_hex32(
            value,
            &format!("governed contract response.lifecycle.emergency_hold.{field}"),
        )?;
    }
    let reason = require_nonempty_string_field(
        object,
        "reason",
        "governed contract response.lifecycle.emergency_hold",
    )?;
    if reason.trim().is_empty() {
        return Err(eyre!(
            "governed contract response.lifecycle.emergency_hold.reason must contain non-whitespace text"
        ));
    }
    let imposed = require_u64_field(
        object,
        "imposed_at_height",
        "governed contract response.lifecycle.emergency_hold",
    )?;
    let expires = require_u64_field(
        object,
        "expires_at_height",
        "governed contract response.lifecycle.emergency_hold",
    )?;
    if imposed == 0 {
        return Err(eyre!(
            "governed contract response.lifecycle.emergency_hold.imposed_at_height must be non-zero"
        ));
    }
    if expires <= imposed {
        return Err(eyre!(
            "governed contract response.lifecycle.emergency_hold.expires_at_height must exceed imposed_at_height"
        ));
    }
    if expires - imposed > MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1 {
        return Err(eyre!(
            "governed contract response.lifecycle.emergency_hold duration must not exceed {MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1} blocks"
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum GovernedContractLifecycleOwner {
    Account(AccountId),
    Parliament,
}

fn parse_contract_lifecycle_owner(
    value: &str,
    context: &str,
) -> Result<GovernedContractLifecycleOwner> {
    if value == "parliament" {
        return Ok(GovernedContractLifecycleOwner::Parliament);
    }
    let account = AccountId::parse_encoded(value).map_err(|error| {
        eyre!("{context} must be `parliament` or a canonical I105 account: {error}")
    })?;
    Ok(GovernedContractLifecycleOwner::Account(account))
}

fn require_contract_lifecycle_owner_field(
    object: &Map,
    field: &str,
    context: &str,
) -> Result<GovernedContractLifecycleOwner> {
    let value = require_nonempty_string_field(object, field, context)?;
    parse_contract_lifecycle_owner(value, &format!("{context}.{field}"))
}

fn require_nullable_contract_lifecycle_owner_field(
    object: &Map,
    field: &str,
    context: &str,
) -> Result<Option<GovernedContractLifecycleOwner>> {
    match object.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => {
            parse_contract_lifecycle_owner(value, &format!("{context}.{field}")).map(Some)
        }
        _ => Err(eyre!(
            "{context}.{field} must be `parliament`, a canonical I105 account, or null"
        )),
    }
}

fn require_canonical_account_id_field(
    object: &Map,
    field: &str,
    context: &str,
) -> Result<AccountId> {
    let value = require_nonempty_string_field(object, field, context)?;
    AccountId::parse_encoded(value)
        .map_err(|error| eyre!("{context}.{field} must be a canonical I105 account: {error}"))
}
fn validate_public_entrypoints(object: &Map) -> Result<()> {
    let values = object
        .get("public_entrypoints")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("governed contract response.public_entrypoints must be an array"))?;
    if values.is_empty() {
        return Err(eyre!(
            "governed contract response.public_entrypoints must not be empty"
        ));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        let name = value.as_str().ok_or_else(|| {
            eyre!("governed contract response.public_entrypoints must contain only strings")
        })?;
        if !is_canonical_public_entrypoint_name(name) {
            return Err(eyre!(
                "governed contract response.public_entrypoints contains invalid entrypoint `{name}`"
            ));
        }
        if previous.is_some_and(|previous| previous >= name) {
            return Err(eyre!(
                "governed contract response.public_entrypoints must be sorted and unique"
            ));
        }
        previous = Some(name);
    }
    Ok(())
}
fn is_canonical_public_entrypoint_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}
fn require_exact_fields(object: &Map, expected: &[&str], context: &str) -> Result<()> {
    let missing = expected
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect::<Vec<_>>();
    let unexpected = object
        .keys()
        .map(String::as_str)
        .filter(|field| !expected.contains(field))
        .collect::<Vec<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        return Err(eyre!(
            "{context} must use the exact fields (missing: {missing:?}; unexpected: {unexpected:?})"
        ));
    }
    Ok(())
}
fn require_bool_field(object: &Map, field: &str, context: &str) -> Result<bool> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| eyre!("{context}.{field} must be a boolean"))
}
fn require_u64_field(object: &Map, field: &str, context: &str) -> Result<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("{context}.{field} must be an unsigned integer"))
}
fn require_nonempty_string_field<'a>(
    object: &'a Map,
    field: &str,
    context: &str,
) -> Result<&'a str> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("{context}.{field} must be a string"))?;
    if value.is_empty() {
        return Err(eyre!("{context}.{field} must not be empty"));
    }
    Ok(value)
}
fn require_null_field(object: &Map, field: &str, context: &str) -> Result<()> {
    match object.get(field) {
        Some(Value::Null) => Ok(()),
        _ => Err(eyre!("{context}.{field} must be null")),
    }
}
fn require_canonical_hex32_field<'a>(
    object: &'a Map,
    field: &str,
    context: &str,
) -> Result<&'a str> {
    let value = require_nonempty_string_field(object, field, context)?;
    let canonical = canonicalize_hex32(value)
        .map_err(|error| eyre!("{context}.{field} must be lowercase 32-byte hex: {error}"))?;
    if canonical != value {
        return Err(eyre!(
            "{context}.{field} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(value)
}
fn require_nonzero_hex32(value: &str, context: &str) -> Result<()> {
    if value.bytes().all(|byte| byte == b'0') {
        return Err(eyre!("{context} must not be all zero"));
    }
    Ok(())
}
fn copy_contract_lifecycle_projection(binding: &Value, record: &mut Map) {
    for field in [
        "contract_subject_account",
        "active",
        "lifecycle",
        "emergency_hold_active",
        "abi_hash_hex",
        "public_entrypoints",
    ] {
        record.insert(
            field.into(),
            binding.get(field).cloned().unwrap_or(Value::Null),
        );
    }
}
fn missing_contract_artifact_issue(found: bool, active: Option<bool>) -> Option<&'static str> {
    match (found, active) {
        (false, _) => Some("contract_binding_missing"),
        (true, Some(false)) => None,
        (true, Some(true)) => Some("contract_binding_missing_code_hash"),
        (true, None) => Some("contract_binding_missing_active_state"),
    }
}
fn finalize_record(
    mut record: Map,
    manifest_map: Map,
    proposal_map: Map,
    code_map: Map,
    issues: Vec<String>,
) -> Value {
    let issue_count = issues.len();
    let has_issues = issue_count > 0;
    record.insert("manifest".into(), Value::Object(manifest_map));
    record.insert("proposal".into(), Value::Object(proposal_map));
    record.insert("code".into(), Value::Object(code_map));
    record.insert(
        "issues".into(),
        Value::Array(issues.into_iter().map(Value::from).collect()),
    );
    record.insert("has_issues".into(), Value::from(has_issues));
    record.insert("issue_count".into(), Value::from(issue_count as u64));
    Value::Object(record)
}
fn audit_manifest_map(
    client: &Client,
    artifact_id: &iroha::data_model::smart_contract::ContractArtifactId,
    manifest_map: &mut Map,
    issues: &mut Vec<String>,
) -> Option<(
    String,
    Option<iroha::data_model::smart_contract::manifest::ManifestProvenance>,
)> {
    let code_hash = hex::encode(artifact_id.code_hash.as_ref());
    let manifest_value = client.get_contract_manifest_json(artifact_id);
    manifest_map.insert("present".into(), Value::from(manifest_value.is_ok()));
    let mut proposal_binding = None;
    match manifest_value {
        Ok(manifest_v) => {
            if let Some(manifest_obj) = manifest_v.get("manifest").and_then(Value::as_object) {
                if let Some(code_hash_str) = manifest_obj.get("code_hash").and_then(Value::as_str) {
                    match canonicalize_hex32(code_hash_str) {
                        Ok(manifest_hash) => {
                            let matches = manifest_hash == code_hash;
                            manifest_map.insert("code_hash".into(), Value::from(manifest_hash));
                            manifest_map.insert("code_hash_matches".into(), Value::from(matches));
                            if !matches {
                                issues.push(format!(
                                    "manifest_code_hash_mismatch: expected={code_hash} got={code_hash_str}"
                                ));
                            }
                        }
                        Err(err) => {
                            manifest_map
                                .insert("code_hash_error".into(), Value::from(err.to_string()));
                            issues.push(format!("manifest_code_hash_invalid: {err}"));
                        }
                    }
                } else {
                    manifest_map.insert("code_hash".into(), Value::Null);
                }
                if let Some(abi_hash_str) = manifest_obj.get("abi_hash").and_then(Value::as_str) {
                    match canonicalize_hex32(abi_hash_str) {
                        Ok(abi_hash) => {
                            manifest_map.insert("abi_hash".into(), Value::from(abi_hash.clone()));
                            match norito::json::from_value::<
                                iroha::data_model::smart_contract::manifest::ContractManifest,
                            >(Value::Object(manifest_obj.clone()))
                            {
                                Ok(manifest) => {
                                    proposal_binding = Some((abi_hash, manifest.provenance));
                                }
                                Err(err) => {
                                    manifest_map.insert(
                                        "provenance_error".into(),
                                        Value::from(err.to_string()),
                                    );
                                    issues.push(format!(
                                        "manifest_provenance_invalid_for_proposal_id: {err}"
                                    ));
                                }
                            }
                        }
                        Err(err) => {
                            manifest_map
                                .insert("abi_hash_error".into(), Value::from(err.to_string()));
                            issues.push(format!("manifest_abi_hash_invalid: {err}"));
                        }
                    }
                } else {
                    manifest_map.insert("abi_hash".into(), Value::Null);
                    issues.push("manifest_missing_abi_hash".into());
                }
            } else {
                manifest_map.insert(
                    "error".into(),
                    Value::from("response missing manifest object"),
                );
                issues.push("manifest_structure_unexpected".into());
            }
        }
        Err(err) => {
            manifest_map.insert("error".into(), Value::from(err.to_string()));
            issues.push(format!("manifest_fetch_error: {err}"));
        }
    }
    proposal_binding
}
fn audit_code_map(
    client: &Client,
    artifact_id: &iroha::data_model::smart_contract::ContractArtifactId,
    code_map: &mut Map,
    issues: &mut Vec<String>,
) {
    let code_hash = hex::encode(artifact_id.code_hash.as_ref());
    match client.get_contract_code_bytes(artifact_id) {
        Ok(bytes) => {
            let length = bytes.len() as u64;
            code_map.insert("present".into(), Value::from(true));
            code_map.insert("length".into(), Value::from(length));
            if bytes.is_empty() {
                code_map.insert("computed_hash".into(), Value::Null);
                code_map.insert("hash_matches".into(), Value::from(false));
                issues.push("code_bytes_empty".into());
            } else {
                let computed = contract_code_hash(&bytes);
                let computed_hex = hex::encode(computed.as_ref());
                let matches = computed_hex == code_hash;
                code_map.insert("computed_hash".into(), Value::from(computed_hex.clone()));
                code_map.insert("hash_matches".into(), Value::from(matches));
                if !matches {
                    issues.push(format!(
                        "code_hash_mismatch: expected={code_hash} computed={computed_hex}"
                    ));
                }
            }
        }
        Err(err) => {
            code_map.insert("present".into(), Value::from(false));
            code_map.insert("error".into(), Value::from(err.to_string()));
            issues.push(format!("code_bytes_error: {err}"));
        }
    }
}
fn audit_proposal_map(
    client: &Client,
    proposal_operator: Option<&AccountId>,
    contract_address: &iroha::data_model::smart_contract::ContractAddress,
    code_hash: &str,
    manifest_binding: Option<&(
        String,
        Option<iroha::data_model::smart_contract::manifest::ManifestProvenance>,
    )>,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) {
    let (Some(proposal_operator), Some((abi_hash_hex, manifest_provenance))) =
        (proposal_operator, manifest_binding)
    else {
        proposal_map.insert("expected_id".into(), Value::Null);
        proposal_map.insert("found".into(), Value::from(false));
        return;
    };
    if let Some(expected_id) = resolve_proposal_id(
        proposal_operator,
        contract_address,
        code_hash,
        abi_hash_hex,
        manifest_provenance.clone(),
        proposal_map,
        issues,
    ) && let Some(proposal_json) =
        fetch_proposal_json(client, &expected_id, proposal_map, issues)
    {
        process_proposal_json(
            &proposal_json,
            contract_address,
            code_hash,
            abi_hash_hex,
            proposal_map,
            issues,
        );
    }
}
fn resolve_proposal_id(
    proposal_operator: &AccountId,
    contract_address: &iroha::data_model::smart_contract::ContractAddress,
    code_hash: &str,
    abi_hash_hex: &str,
    manifest_provenance: Option<iroha::data_model::smart_contract::manifest::ManifestProvenance>,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) -> Option<String> {
    match (decode_hex32(code_hash), decode_hex32(abi_hash_hex)) {
        (Ok(code_bytes), Ok(abi_bytes)) => {
            let proposal_id_bytes = compute_proposal_id(
                proposal_operator,
                contract_address,
                &code_bytes,
                &abi_bytes,
                manifest_provenance,
            );
            let proposal_id_hex = hex::encode(proposal_id_bytes);
            proposal_map.insert("expected_id".into(), Value::from(proposal_id_hex.clone()));
            Some(proposal_id_hex)
        }
        (Err(err), _) => {
            proposal_map.insert("expected_id".into(), Value::Null);
            proposal_map.insert("found".into(), Value::from(false));
            issues.push(format!("code_hash_decode_error: {err}"));
            None
        }
        (_, Err(err)) => {
            proposal_map.insert("expected_id".into(), Value::Null);
            proposal_map.insert("found".into(), Value::from(false));
            issues.push(format!("abi_hash_decode_error: {err}"));
            None
        }
    }
}
fn fetch_proposal_json(
    client: &Client,
    proposal_id_hex: &str,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) -> Option<Value> {
    match client.get_gov_proposal_json(proposal_id_hex) {
        Ok(value) => Some(value),
        Err(err) => {
            proposal_map.insert("found".into(), Value::from(false));
            proposal_map.insert("error".into(), Value::from(err.to_string()));
            issues.push(format!("proposal_fetch_error: {err}"));
            None
        }
    }
}
fn process_proposal_json(
    proposal_json: &Value,
    contract_address: &iroha::data_model::smart_contract::ContractAddress,
    code_hash: &str,
    abi_hash_hex: &str,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) {
    let found = proposal_json
        .get("found")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    proposal_map.insert("found".into(), Value::from(found));
    if !found {
        issues.push("proposal_missing".into());
        return;
    }
    let Some(proposal_obj) = proposal_json.get("proposal").and_then(Value::as_object) else {
        return;
    };
    update_status(proposal_obj, proposal_map, issues);
    if let Some(kind_obj) = proposal_obj.get("kind").and_then(Value::as_object) {
        if let Some(deploy_obj) = kind_obj.get("DeployContract").and_then(Value::as_object) {
            audit_deploy_contract(
                deploy_obj,
                contract_address,
                code_hash,
                abi_hash_hex,
                proposal_map,
                issues,
            );
        } else {
            issues.push("proposal_kind_not_deploy_contract".into());
        }
    }
}
fn update_status(proposal_obj: &Map, proposal_map: &mut Map, issues: &mut Vec<String>) {
    if let Some(status) = proposal_obj.get("status").and_then(Value::as_str) {
        proposal_map.insert("status".into(), Value::from(status));
        if status != "Enacted" {
            issues.push(format!("proposal_status_not_enacted: {status}"));
        }
    } else {
        issues.push("proposal_status_missing".into());
    }
}
fn audit_deploy_contract(
    deploy_obj: &Map,
    contract_address: &iroha::data_model::smart_contract::ContractAddress,
    code_hash: &str,
    abi_hash_hex: &str,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) {
    check_contract_address(deploy_obj, contract_address, proposal_map, issues);
    check_hex_field(
        deploy_obj,
        &HexFieldContext {
            source_key: "code_hash_hex",
            expected: code_hash,
            map_value_key: "code_hash_hex",
            matches_key: "code_hash_matches",
            error_key: "code_hash_error",
            mismatch_issue: "proposal_code_hash_mismatch",
            invalid_issue: "proposal_code_hash_invalid",
        },
        proposal_map,
        issues,
    );
    check_hex_field(
        deploy_obj,
        &HexFieldContext {
            source_key: "abi_hash_hex",
            expected: abi_hash_hex,
            map_value_key: "abi_hash_hex",
            matches_key: "abi_hash_matches",
            error_key: "abi_hash_error",
            mismatch_issue: "proposal_abi_hash_mismatch",
            invalid_issue: "proposal_abi_hash_invalid",
        },
        proposal_map,
        issues,
    );
}
fn check_contract_address(
    deploy_obj: &Map,
    expected: &iroha::data_model::smart_contract::ContractAddress,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) {
    let contract_value = deploy_obj
        .get("contract_address")
        .cloned()
        .unwrap_or(Value::Null);
    let contract_match = contract_value.as_str() == Some(expected.as_ref());
    proposal_map.insert("contract_address".into(), contract_value);
    if !contract_match {
        issues.push("proposal_contract_address_mismatch".into());
    }
}
#[derive(Clone, Copy)]
struct HexFieldContext<'a> {
    source_key: &'a str,
    expected: &'a str,
    map_value_key: &'a str,
    matches_key: &'a str,
    error_key: &'a str,
    mismatch_issue: &'static str,
    invalid_issue: &'static str,
}
fn check_hex_field(
    deploy_obj: &Map,
    ctx: &HexFieldContext<'_>,
    proposal_map: &mut Map,
    issues: &mut Vec<String>,
) {
    if let Some(prop_hash) = deploy_obj.get(ctx.source_key).and_then(Value::as_str) {
        match canonicalize_hex32(prop_hash) {
            Ok(canonical) => {
                let matches = canonical == ctx.expected;
                proposal_map.insert(ctx.map_value_key.into(), Value::from(canonical.clone()));
                proposal_map.insert(ctx.matches_key.into(), Value::from(matches));
                if !matches {
                    issues.push(ctx.mismatch_issue.into());
                }
            }
            Err(err) => {
                proposal_map.insert(ctx.error_key.into(), Value::from(err.to_string()));
                issues.push(format!("{}: {err}", ctx.invalid_issue));
            }
        }
    } else {
        proposal_map.insert(ctx.map_value_key.into(), Value::Null);
        issues.push(ctx.invalid_issue.into());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};

    const CONTRACT_ADDRESS: &str = "contract:test:governed-audit";

    fn account_id(seed: u8) -> String {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive deterministic account key");
        AccountId::new(keypair.public_key().clone()).to_string()
    }

    fn lifecycle(active_code_hash_hex: Option<&str>) -> Value {
        let origin_account = account_id(0x41);
        let owner = account_id(0x42);
        norito::json!({
            "version": 1,
            "origin": "direct",
            "origin_account": origin_account,
            "origin_proposal_content_id_hex": null,
            "origin_governance_attempt_id_hex": null,
            "owner": owner,
            "pending_owner": null,
            "parliament_delegated": false,
            "active_code_hash_hex": active_code_hash_hex,
            "retained_code_hash_hex": active_code_hash_hex,
            "revision": 1,
            "emergency_hold": null
        })
    }

    #[test]
    fn suspended_lifecycle_keeps_its_required_schema_binding() {
        let mut retained = lifecycle(None);
        retained.as_object_mut().unwrap().insert(
            "retained_code_hash_hex".into(),
            Value::from("22".repeat(32)),
        );
        validate_governed_contract_lifecycle(&retained, None, false)
            .expect("suspended binding is preserved");
        retained
            .as_object_mut()
            .unwrap()
            .remove("retained_code_hash_hex");
        assert!(validate_governed_contract_lifecycle(&retained, None, false).is_err());
        let mut active = lifecycle(Some(&"22".repeat(32)));
        active.as_object_mut().unwrap().insert(
            "retained_code_hash_hex".into(),
            Value::from("33".repeat(32)),
        );
        assert!(
            validate_governed_contract_lifecycle(&active, Some(&"22".repeat(32)), false).is_err()
        );
    }

    fn inactive_binding() -> Value {
        norito::json!({
            "found": true,
            "contract_address": CONTRACT_ADDRESS,
            "contract_subject_account": "ed0120subject",
            "dataspace": "universal",
            "active": false,
            "lifecycle": (lifecycle(None)),
            "emergency_hold_active": false
        })
    }

    fn active_binding() -> Value {
        let code_hash = "11".repeat(32);
        norito::json!({
            "found": true,
            "contract_address": CONTRACT_ADDRESS,
            "contract_subject_account": "ed0120subject",
            "dataspace": "universal",
            "active": true,
            "lifecycle": (lifecycle(Some(&code_hash))),
            "emergency_hold_active": false,
            "code_hash_hex": code_hash,
            "abi_hash_hex": ("22".repeat(32)),
            "public_entrypoints": ["balance", "transfer"]
        })
    }

    #[test]
    fn strict_governed_contract_binding_accepts_exact_closed_shapes() {
        let missing = norito::json!({
            "found": false,
            "contract_address": CONTRACT_ADDRESS,
            "dataspace": "universal"
        });
        let validated = validate_governed_contract_binding(&missing, CONTRACT_ADDRESS)
            .expect("exact missing shape");
        assert!(!validated.found);
        assert_eq!(validated.active, None);
        assert_eq!(validated.code_hash_hex, None);

        let inactive = inactive_binding();
        let validated = validate_governed_contract_binding(&inactive, CONTRACT_ADDRESS)
            .expect("exact inactive shape");
        assert!(validated.found);
        assert_eq!(validated.active, Some(false));
        assert_eq!(validated.code_hash_hex, None);

        let active = active_binding();
        let validated = validate_governed_contract_binding(&active, CONTRACT_ADDRESS)
            .expect("exact active shape");
        assert_eq!(validated.active, Some(true));
        let expected_code_hash = "11".repeat(32);
        assert_eq!(validated.code_hash_hex, Some(expected_code_hash.as_str()));
    }

    #[test]
    fn strict_governed_contract_binding_rejects_open_or_incomplete_shapes() {
        let cases = [
            (
                norito::json!({
                    "found": true,
                    "contract_address": CONTRACT_ADDRESS,
                    "dataspace": "universal",
                    "active": false
                }),
                "missing",
            ),
            (
                norito::json!({
                    "found": false,
                    "contract_address": CONTRACT_ADDRESS,
                    "dataspace": "universal",
                    "active": null
                }),
                "unexpected",
            ),
        ];
        for (binding, expected) in cases {
            let error = validate_governed_contract_binding(&binding, CONTRACT_ADDRESS)
                .expect_err("open or incomplete governed-contract response must fail");
            assert!(
                error.to_string().contains(expected),
                "unexpected validation error: {error:#}"
            );
        }
    }

    #[test]
    fn strict_governed_contract_binding_rejects_lifecycle_and_artifact_mismatches() {
        let mut inactive = inactive_binding();
        inactive
            .as_object_mut()
            .expect("inactive object")
            .get_mut("lifecycle")
            .and_then(Value::as_object_mut)
            .expect("lifecycle object")
            .remove("revision");
        let error = validate_governed_contract_binding(&inactive, CONTRACT_ADDRESS)
            .expect_err("incomplete lifecycle must fail");
        assert!(error.to_string().contains("revision"), "{error:#}");

        let mut active = active_binding();
        active
            .as_object_mut()
            .expect("active object")
            .get_mut("lifecycle")
            .and_then(Value::as_object_mut)
            .expect("lifecycle object")
            .insert("active_code_hash_hex".into(), Value::from("33".repeat(32)));
        let error = validate_governed_contract_binding(&active, CONTRACT_ADDRESS)
            .expect_err("mismatched active lifecycle hash must fail");
        assert!(
            error.to_string().contains("must match code_hash_hex"),
            "{error:#}"
        );

        let mut active = active_binding();
        active.as_object_mut().expect("active object").insert(
            "public_entrypoints".into(),
            norito::json!(["transfer", "balance"]),
        );
        let error = validate_governed_contract_binding(&active, CONTRACT_ADDRESS)
            .expect_err("unsorted active entrypoints must fail");
        assert!(error.to_string().contains("sorted and unique"), "{error:#}");
    }

    #[test]
    fn strict_governed_contract_lifecycle_rejects_consensus_impossible_values() {
        let mut cases = Vec::new();

        let mut invalid_origin_account = lifecycle(None);
        invalid_origin_account
            .as_object_mut()
            .expect("lifecycle object")
            .insert("origin_account".into(), Value::from("not-an-account"));
        cases.push((invalid_origin_account, "origin_account"));

        let mut invalid_owner = lifecycle(None);
        invalid_owner
            .as_object_mut()
            .expect("lifecycle object")
            .insert("owner".into(), Value::from("not-an-account"));
        cases.push((invalid_owner, "owner"));

        let mut duplicate_owner_offer = lifecycle(None);
        let owner = duplicate_owner_offer
            .as_object()
            .and_then(|object| object.get("owner"))
            .cloned()
            .expect("owner field");
        duplicate_owner_offer
            .as_object_mut()
            .expect("lifecycle object")
            .insert("pending_owner".into(), owner);
        cases.push((duplicate_owner_offer, "must differ"));

        let mut parliament_with_delegation = lifecycle(None);
        let object = parliament_with_delegation
            .as_object_mut()
            .expect("lifecycle object");
        object.insert("owner".into(), Value::from("parliament"));
        object.insert("parliament_delegated".into(), Value::from(true));
        cases.push((parliament_with_delegation, "must be false"));

        let mut zero_parliament_origin = lifecycle(None);
        let object = zero_parliament_origin
            .as_object_mut()
            .expect("lifecycle object");
        object.insert("origin".into(), Value::from("parliament"));
        object.insert(
            "origin_proposal_content_id_hex".into(),
            Value::from("00".repeat(32)),
        );
        object.insert(
            "origin_governance_attempt_id_hex".into(),
            Value::from("11".repeat(32)),
        );
        cases.push((zero_parliament_origin, "must not be all zero"));

        for (field, value, expected) in [
            (
                "incident_digest_hex",
                Value::from("00".repeat(32)),
                "must not be all zero",
            ),
            ("reason", Value::from(" \t "), "non-whitespace"),
            ("imposed_at_height", Value::from(0_u64), "must be non-zero"),
            (
                "expires_at_height",
                Value::from(MAX_CONTRACT_EMERGENCY_HOLD_BLOCKS_V1 + 2),
                "must not exceed",
            ),
        ] {
            let mut lifecycle = lifecycle(None);
            lifecycle.as_object_mut().expect("lifecycle object").insert(
                "emergency_hold".into(),
                norito::json!({
                    "incident_digest_hex": ("11".repeat(32)),
                    "proposal_content_id_hex": ("22".repeat(32)),
                    "governance_attempt_id_hex": ("33".repeat(32)),
                    "reason": "containment",
                    "imposed_at_height": 1,
                    "expires_at_height": 2
                }),
            );
            lifecycle
                .as_object_mut()
                .and_then(|object| object.get_mut("emergency_hold"))
                .and_then(Value::as_object_mut)
                .expect("emergency hold object")
                .insert(field.into(), value);
            cases.push((lifecycle, expected));
        }

        for (lifecycle, expected) in cases {
            let error = validate_governed_contract_lifecycle(&lifecycle, None, false)
                .expect_err("consensus-impossible lifecycle must fail closed");
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in validation error: {error:#}"
            );
        }
    }

    #[test]
    fn audit_projection_retains_complete_contract_lifecycle_state() {
        let proposer = account_id(0x51);
        let owner = account_id(0x52);
        let binding = norito::json!({
            "contract_subject_account": "ed0120subject",
            "active": false,
            "lifecycle": {
                "version": 1,
                "origin": "parliament",
                "origin_account": proposer,
                "origin_proposal_content_id_hex": ("11".repeat(32)),
                "origin_governance_attempt_id_hex": ("22".repeat(32)),
                "owner": owner,
                "pending_owner": "parliament",
                "parliament_delegated": true,
                "active_code_hash_hex": null,
                "retained_code_hash_hex": null,
                "revision": 7,
                "emergency_hold": {
                    "incident_digest_hex": ("33".repeat(32)),
                    "proposal_content_id_hex": ("44".repeat(32)),
                    "governance_attempt_id_hex": ("55".repeat(32)),
                    "reason": "containment",
                    "imposed_at_height": 10,
                    "expires_at_height": 20
                }
            },
            "emergency_hold_active": true,
            "abi_hash_hex": null,
            "public_entrypoints": []
        });
        let mut record = Map::new();

        copy_contract_lifecycle_projection(&binding, &mut record);

        assert_eq!(record.get("lifecycle"), binding.get("lifecycle"));
        assert_eq!(
            record.get("emergency_hold_active"),
            Some(&Value::from(true))
        );
        assert_eq!(
            record
                .get("lifecycle")
                .and_then(Value::as_object)
                .and_then(|lifecycle| lifecycle.get("pending_owner"))
                .and_then(Value::as_str),
            Some("parliament")
        );
    }

    #[test]
    fn audit_projection_represents_absent_lifecycle_fields_explicitly() {
        let mut record = Map::new();
        copy_contract_lifecycle_projection(&norito::json!({}), &mut record);
        for field in [
            "contract_subject_account",
            "active",
            "lifecycle",
            "emergency_hold_active",
            "abi_hash_hex",
            "public_entrypoints",
        ] {
            assert_eq!(record.get(field), Some(&Value::Null));
        }
    }

    #[test]
    fn inactive_lifecycle_without_artifact_is_not_an_audit_issue() {
        assert_eq!(missing_contract_artifact_issue(true, Some(false)), None);
        assert_eq!(
            missing_contract_artifact_issue(true, Some(true)),
            Some("contract_binding_missing_code_hash")
        );
        assert_eq!(
            missing_contract_artifact_issue(true, None),
            Some("contract_binding_missing_active_state")
        );
        assert_eq!(
            missing_contract_artifact_issue(false, None),
            Some("contract_binding_missing")
        );
    }
}
