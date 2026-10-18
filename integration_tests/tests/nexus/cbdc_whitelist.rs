//! Nexus CBDC whitelist validation workflow.
#![cfg(target_family = "unix")]
use eyre::{Result, WrapErr, ensure, eyre};
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::AssetDefinitionId,
    nexus::{
        Allowance, AllowanceWindow, AmxRole, AssetPermissionManifest, CapabilityRequest,
        CapabilityScope, DenyDirective, DenyReason, ManifestEffect, ManifestEntry, ManifestVerdict,
        ManifestVersion, SmartContractId, UniversalAccountId,
    },
};
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use norito::{decode_from_bytes, json::Value, to_bytes};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration_tests workspace root")
        .to_path_buf()
}
fn profile_path(root: &Path) -> PathBuf {
    root.join("fixtures/space_directory/profile/cbdc_lane_profile.json")
}
fn load_cbdc_profile() -> Result<(Value, PathBuf)> {
    let root = repo_root();
    let path = profile_path(&root);
    ensure!(
        path.is_file(),
        "CBDC profile not found at {}",
        path.display()
    );
    let profile_dir = path
        .parent()
        .ok_or_else(|| eyre!("CBDC profile missing parent directory"))?
        .to_path_buf();
    let profile_text =
        fs::read_to_string(&path).wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let profile: Value =
        norito::json::from_str(&profile_text).wrap_err("failed to parse CBDC profile JSON")?;
    Ok((profile, profile_dir))
}
fn parse_uaid(value: &str) -> Result<UniversalAccountId> {
    UniversalAccountId::from_str(value).wrap_err_with(|| {
        format!("invalid UAID literal {value} (expected exact `uaid:<64-lowercase-hex>`)")
    })
}
#[test]
fn parse_uaid_accepts_only_exact_canonical_literal() {
    let hash = Hash::new(b"cbdc-whitelist-uaid");
    let hex = hash.to_string();
    let prefixed = format!("uaid:{hex}");
    let expected = UniversalAccountId::from_hash(hash);
    let parsed_prefixed = parse_uaid(&prefixed).expect("parse prefixed UAID");
    assert_eq!(parsed_prefixed, expected);
    for retired in [
        hex.clone(),
        format!("UAID:{hex}"),
        format!("uaid:{}", hex.to_uppercase()),
        format!(" {prefixed}"),
        format!("{prefixed} "),
    ] {
        assert!(
            parse_uaid(&retired).is_err(),
            "noncanonical UAID spelling must fail"
        );
    }
}
fn parse_numeric(value: &Value, context: &str) -> Result<Quantity> {
    let raw = match value {
        Value::String(text) => text.clone(),
        _ => norito::json::to_string(value)
            .wrap_err_with(|| format!("{context}: failed to format numeric literal"))?,
    };
    Quantity::from_str(&raw)
        .wrap_err_with(|| format!("{context}: failed to parse numeric value {raw}"))
}
fn parse_role(value: Option<&Value>, context: &str) -> Result<Option<AmxRole>> {
    match value.and_then(Value::as_str) {
        Some("Initiator") => Ok(Some(AmxRole::Initiator)),
        Some("Participant") => Ok(Some(AmxRole::Participant)),
        Some(other) => Err(eyre!("{context}: unsupported AMX role {other}")),
        None => Ok(None),
    }
}
fn parse_window(value: &Value, context: &str) -> Result<AllowanceWindow> {
    match value.as_str() {
        Some("PerSlot") => Ok(AllowanceWindow::PerSlot),
        Some("PerMinute") => Ok(AllowanceWindow::PerMinute),
        Some("PerDay") => Ok(AllowanceWindow::PerDay),
        Some(other) => Err(eyre!("{context}: unsupported allowance window {other}")),
        None => Err(eyre!("{context}: allowance window must be a string")),
    }
}
#[allow(clippy::too_many_lines)]
fn decode_capability_manifest(value: &Value) -> Result<AssetPermissionManifest> {
    let manifest_obj = value
        .as_object()
        .ok_or_else(|| eyre!("capability manifest must be a JSON object"))?;
    let version_value = manifest_obj
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("capability manifest missing version"))?;
    let version = match version_value {
        1 => ManifestVersion::V1,
        other => return Err(eyre!("unsupported capability manifest version {other}")),
    };
    let uaid_value = manifest_obj
        .get("uaid")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("capability manifest missing uaid field"))?;
    let uaid = parse_uaid(uaid_value)?;
    let dataspace_value = manifest_obj
        .get("dataspace")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("capability manifest missing dataspace field"))?;
    let issued_ms = manifest_obj
        .get("issued_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("capability manifest missing issued_ms field"))?;
    let activation_epoch = manifest_obj
        .get("activation_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("capability manifest missing activation_epoch field"))?;
    let expiry_epoch = manifest_obj.get("expiry_epoch").and_then(Value::as_u64);
    let entries_value = manifest_obj
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("capability manifest missing entries array"))?;
    let mut entries: Vec<ManifestEntry> = Vec::with_capacity(entries_value.len());
    for (idx, entry_value) in entries_value.iter().enumerate() {
        let entry_obj = entry_value
            .as_object()
            .ok_or_else(|| eyre!("manifest entry #{idx} must be a JSON object"))?;
        let scope_obj = entry_obj
            .get("scope")
            .and_then(Value::as_object)
            .ok_or_else(|| eyre!("manifest entry #{idx} missing scope object"))?;
        let scope = CapabilityScope {
            dataspace: scope_obj
                .get("dataspace")
                .and_then(Value::as_u64)
                .map(DataSpaceId::from),
            program: scope_obj
                .get("program")
                .and_then(Value::as_str)
                .map(SmartContractId::from_str)
                .transpose()
                .wrap_err_with(|| format!("manifest entry #{idx} contains invalid program"))?,
            method: scope_obj
                .get("method")
                .and_then(Value::as_str)
                .map(Name::from_str)
                .transpose()
                .wrap_err_with(|| format!("manifest entry #{idx} contains invalid method"))?,
            asset: scope_obj
                .get("asset")
                .and_then(Value::as_str)
                .map(AssetDefinitionId::from_str)
                .transpose()
                .wrap_err_with(|| format!("manifest entry #{idx} contains invalid asset id"))?,
            role: parse_role(
                scope_obj.get("role"),
                &format!("manifest entry #{idx} role"),
            )?,
        };
        let effect_value = entry_obj
            .get("effect")
            .and_then(Value::as_object)
            .ok_or_else(|| eyre!("manifest entry #{idx} missing effect object"))?;
        ensure!(
            effect_value.len() == 1,
            "manifest entry #{idx} effect must contain exactly one decision"
        );
        let (decision, details_value) = effect_value.iter().next().expect("non-empty effect");
        let effect = match decision.as_str() {
            "Allow" => {
                let detail_obj = details_value
                    .as_object()
                    .ok_or_else(|| eyre!("manifest entry #{idx} allow effect must be an object"))?;
                let max_amount = detail_obj
                    .get("max_amount")
                    .map(|raw| parse_numeric(raw, &format!("manifest entry #{idx} max_amount")))
                    .transpose()?;
                let window_value = detail_obj.get("window").ok_or_else(|| {
                    eyre!("manifest entry #{idx} allow effect missing window field")
                })?;
                let window = parse_window(window_value, &format!("manifest entry #{idx} window"))?;
                ManifestEffect::Allow(Allowance { max_amount, window })
            }
            "Deny" => {
                let detail_obj = details_value
                    .as_object()
                    .ok_or_else(|| eyre!("manifest entry #{idx} deny effect must be an object"))?;
                let reason = detail_obj
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                ManifestEffect::Deny(DenyDirective { reason })
            }
            other => {
                return Err(eyre!(
                    "manifest entry #{idx} has unsupported effect {other}"
                ));
            }
        };
        let notes = entry_obj
            .get("notes")
            .and_then(Value::as_str)
            .map(str::to_owned);
        entries.push(ManifestEntry {
            scope,
            effect,
            notes,
        });
    }
    Ok(AssetPermissionManifest {
        version,
        uaid,
        dataspace: DataSpaceId::from(dataspace_value),
        issued_ms,
        activation_epoch,
        expiry_epoch,
        entries,
    })
}
#[test]
#[allow(clippy::too_many_lines)]
fn cbdc_whitelist_entries_match_capability_manifests() -> Result<()> {
    let (profile, profile_dir) = load_cbdc_profile()?;
    let profile_obj = profile
        .as_object()
        .ok_or_else(|| eyre!("CBDC profile must be a JSON object"))?;
    let group = profile_obj
        .get("composability_group")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("cbdc profile missing composability_group object"))?;
    let group_id_hex = group
        .get("group_id_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("composability_group missing group_id_hex"))?;
    ensure!(
        group_id_hex.len() == 64 && group_id_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "group_id_hex {group_id_hex} must be 64 hex characters"
    );
    let activation_epoch = group
        .get("activation_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("composability_group missing activation_epoch"))?;
    ensure!(
        activation_epoch > 0,
        "activation_epoch must be non-zero (got {activation_epoch})"
    );
    let whitelist = group
        .get("whitelist")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("composability_group missing whitelist array"))?;
    ensure!(
        !whitelist.is_empty(),
        "composability_group whitelist must not be empty"
    );
    let mut seen_uaids = HashSet::new();
    for entry in whitelist {
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| eyre!("whitelist entry must be a JSON object"))?;
        let dataspace = entry_obj
            .get("dataspace")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("whitelist entry missing dataspace"))?;
        ensure!(
            dataspace > 0,
            "dataspace must be positive (got {dataspace})"
        );
        let uaid = entry_obj
            .get("uaid")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("whitelist entry missing uaid"))?
            .to_owned();
        let uaid_hex = uaid
            .strip_prefix("uaid:")
            .ok_or_else(|| eyre!("UAID {uaid} must start with 'uaid:'"))?;
        ensure!(
            uaid_hex.len() == 64
                && uaid_hex
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "UAID {uaid} must contain an exact 64-character lowercase-hex suffix"
        );
        ensure!(
            seen_uaids.insert(uaid.clone()),
            "duplicate UAID {uaid} found in whitelist"
        );
        let manifest_rel = entry_obj
            .get("capability_manifest")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("whitelist entry missing capability_manifest path"))?;
        let manifest_rel_path = Path::new(manifest_rel);
        ensure!(
            manifest_rel_path.is_relative(),
            "capability manifest path {manifest_rel} must be relative"
        );
        let manifest_path = profile_dir.join(manifest_rel_path);
        ensure!(
            manifest_path.is_file(),
            "capability manifest {} not found",
            manifest_path.display()
        );
        let manifest_text = fs::read_to_string(&manifest_path).wrap_err_with(|| {
            format!(
                "failed to read capability manifest {}",
                manifest_path.display()
            )
        })?;
        let manifest: Value = norito::json::from_str(&manifest_text).wrap_err_with(|| {
            format!(
                "failed to parse capability manifest {}",
                manifest_path.display()
            )
        })?;
        let manifest_obj = manifest
            .as_object()
            .ok_or_else(|| eyre!("capability manifest must be a JSON object"))?;
        let manifest_uaid = manifest_obj
            .get("uaid")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("capability manifest missing uaid field"))?;
        ensure!(
            manifest_uaid == uaid,
            "capability manifest UAID {manifest_uaid} does not match whitelist entry {uaid}"
        );
        let manifest_dataspace = manifest_obj
            .get("dataspace")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("capability manifest missing dataspace"))?;
        ensure!(
            manifest_dataspace == dataspace,
            "capability manifest dataspace {manifest_dataspace} does not match whitelist entry {dataspace}"
        );
        let manifest_activation_epoch = manifest_obj
            .get("activation_epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("capability manifest missing activation_epoch"))?;
        ensure!(
            manifest_activation_epoch >= activation_epoch,
            "capability manifest activation_epoch {manifest_activation_epoch} must be >= group activation_epoch {activation_epoch}"
        );
        let entries = manifest_obj
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("capability manifest missing entries array"))?;
        ensure!(
            !entries.is_empty(),
            "capability manifest {} must contain at least one entry",
            manifest_path.display()
        );
    }
    Ok(())
}
#[test]
#[allow(clippy::too_many_lines)]
fn cbdc_capability_manifests_enforce_policy_semantics() -> Result<()> {
    let (profile, profile_dir) = load_cbdc_profile()?;
    let profile_obj = profile
        .as_object()
        .ok_or_else(|| eyre!("CBDC profile must be a JSON object"))?;
    let audit_hooks = profile_obj
        .get("audit_hooks")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("cbdc profile missing audit_hooks object"))?;
    let events = audit_hooks
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("audit_hooks missing events array"))?;
    ensure!(
        events.iter().any(|event| {
            matches!(
                event.as_str(),
                Some("SpaceDirectoryEvent.ManifestActivated")
            )
        }),
        "audit_hooks.events must include SpaceDirectoryEvent.ManifestActivated"
    );
    ensure!(
        events
            .iter()
            .any(|event| { matches!(event.as_str(), Some("SpaceDirectoryEvent.ManifestRevoked")) }),
        "audit_hooks.events must include SpaceDirectoryEvent.ManifestRevoked"
    );
    let log_schema = audit_hooks
        .get("log_schema")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("audit_hooks missing log_schema"))?;
    ensure!(
        !log_schema.trim().is_empty(),
        "audit_hooks.log_schema must not be empty"
    );
    let pagerduty_service = audit_hooks
        .get("pagerduty_service")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("audit_hooks missing pagerduty_service"))?;
    ensure!(
        !pagerduty_service.trim().is_empty(),
        "audit_hooks.pagerduty_service must not be empty"
    );
    let group = profile_obj
        .get("composability_group")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("cbdc profile missing composability_group object"))?;
    let whitelist = group
        .get("whitelist")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("composability_group missing whitelist array"))?;
    ensure!(
        !whitelist.is_empty(),
        "composability_group whitelist must not be empty"
    );
    for entry in whitelist {
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| eyre!("whitelist entry must be a JSON object"))?;
        let dataspace = entry_obj
            .get("dataspace")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("whitelist entry missing dataspace"))?;
        let uaid = entry_obj
            .get("uaid")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("whitelist entry missing uaid"))?
            .to_owned();
        let manifest_rel = entry_obj
            .get("capability_manifest")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("whitelist entry missing capability_manifest path"))?;
        let manifest_path = profile_dir.join(Path::new(manifest_rel));
        ensure!(
            manifest_path.is_file(),
            "capability manifest {} not found",
            manifest_path.display()
        );
        let manifest_text = fs::read_to_string(&manifest_path).wrap_err_with(|| {
            format!(
                "failed to read capability manifest {}",
                manifest_path.display()
            )
        })?;
        let manifest_value: Value = norito::json::from_str(&manifest_text).wrap_err_with(|| {
            format!(
                "failed to parse capability manifest {}",
                manifest_path.display()
            )
        })?;
        let manifest_obj = manifest_value
            .as_object()
            .ok_or_else(|| eyre!("capability manifest must be a JSON object"))?;
        let manifest_uaid = manifest_obj
            .get("uaid")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("capability manifest missing uaid field"))?;
        ensure!(
            manifest_uaid == uaid,
            "capability manifest UAID {manifest_uaid} does not match whitelist entry {uaid}"
        );
        let manifest_dataspace = manifest_obj
            .get("dataspace")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("capability manifest missing dataspace"))?;
        ensure!(
            manifest_dataspace == dataspace,
            "capability manifest dataspace {manifest_dataspace} does not match whitelist entry {dataspace}"
        );
        let manifest_activation_epoch = manifest_obj
            .get("activation_epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("capability manifest missing activation_epoch"))?;
        ensure!(
            manifest_activation_epoch > 0,
            "capability manifest activation_epoch must be positive"
        );
        let entries = manifest_obj
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("capability manifest missing entries array"))?;
        ensure!(
            !entries.is_empty(),
            "capability manifest {} must contain at least one entry",
            manifest_path.display()
        );
        let manifest = decode_capability_manifest(&manifest_value)?;
        let encoded_path = manifest_path.with_extension("to");
        ensure!(
            encoded_path.is_file(),
            "capability manifest {} missing Norito fixture {}",
            manifest_path.display(),
            encoded_path.display()
        );
        let encoded_bytes = fs::read(&encoded_path).wrap_err_with(|| {
            format!(
                "failed to read Norito manifest fixture {}",
                encoded_path.display()
            )
        })?;
        let decoded_bytes: AssetPermissionManifest = decode_from_bytes(&encoded_bytes)
            .wrap_err_with(|| {
                format!(
                    "failed to decode Norito manifest bytes from {}",
                    encoded_path.display()
                )
            })?;
        ensure!(
            decoded_bytes == manifest,
            "Norito manifest {} decoded to a value different from {}",
            encoded_path.display(),
            manifest_path.display()
        );
        let canonical_bytes = to_bytes(&manifest).wrap_err_with(|| {
            format!(
                "failed to encode canonical Norito payload for {}",
                manifest_path.display()
            )
        })?;
        ensure!(
            canonical_bytes == encoded_bytes,
            "Norito manifest {} does not match canonical encoding of {}",
            encoded_path.display(),
            manifest_path.display()
        );
        ensure!(
            manifest.version == ManifestVersion::V1,
            "capability manifest {} must declare version 1",
            manifest_path.display()
        );
        let (allow_idx, allow_scope, allowance) = manifest
            .entries
            .iter()
            .enumerate()
            .find_map(|(idx, entry)| match &entry.effect {
                ManifestEffect::Allow(allowance) => Some((idx, &entry.scope, allowance)),
                ManifestEffect::Deny(_) => None,
            })
            .ok_or_else(|| {
                eyre!(
                    "capability manifest {} must contain at least one allow entry",
                    manifest_path.display()
                )
            })?;
        let allow_dataspace = allow_scope.dataspace.unwrap_or(manifest.dataspace);
        let allow_max_amount = allowance.max_amount.clone();
        let allow_request = CapabilityRequest::new(
            allow_dataspace,
            allow_scope.program.as_ref(),
            allow_scope.method.as_ref(),
            allow_scope.asset.as_ref(),
            allow_scope.role,
            allow_max_amount.clone(),
            manifest.activation_epoch,
        );
        let allow_idx_u32 = u32::try_from(allow_idx).map_err(|_| {
            eyre!(
                "capability manifest {} enumerated more allow entries than u32::MAX supports",
                manifest_path.display()
            )
        })?;
        match manifest.evaluate(&allow_request) {
            ManifestVerdict::Allowed(grant) => ensure!(
                grant.entry_index == allow_idx_u32,
                "capability manifest {} returned unexpected allow index {}, expected {}",
                manifest_path.display(),
                grant.entry_index,
                allow_idx
            ),
            verdict => {
                return Err(eyre!(
                    "capability manifest {} failed to allow request: {:?}",
                    manifest_path.display(),
                    verdict
                ));
            }
        }
        if let Some(expiry) = manifest.expiry_epoch {
            let stale_request = CapabilityRequest::new(
                allow_dataspace,
                allow_scope.program.as_ref(),
                allow_scope.method.as_ref(),
                allow_scope.asset.as_ref(),
                allow_scope.role,
                allow_max_amount,
                expiry + 1,
            );
            ensure!(
                matches!(
                    manifest.evaluate(&stale_request),
                    ManifestVerdict::Denied(DenyReason::ManifestInactive { .. })
                ),
                "capability manifest {} must deny requests after expiry_epoch {}",
                manifest_path.display(),
                expiry
            );
        }
        let (deny_idx, deny_scope) = manifest
            .entries
            .iter()
            .enumerate()
            .find_map(|(idx, entry)| match entry.effect {
                ManifestEffect::Deny(_) => Some((idx, &entry.scope)),
                ManifestEffect::Allow(_) => None,
            })
            .ok_or_else(|| {
                eyre!(
                    "capability manifest {} must include a deny entry to enforce revoke semantics",
                    manifest_path.display()
                )
            })?;
        let deny_dataspace = deny_scope.dataspace.unwrap_or(manifest.dataspace);
        let deny_request = CapabilityRequest::new(
            deny_dataspace,
            deny_scope.program.as_ref(),
            deny_scope.method.as_ref(),
            deny_scope.asset.as_ref(),
            deny_scope.role,
            None,
            manifest.activation_epoch,
        );
        let deny_idx_u32 = u32::try_from(deny_idx).map_err(|_| {
            eyre!(
                "capability manifest {} enumerated more deny entries than u32::MAX supports",
                manifest_path.display()
            )
        })?;
        ensure!(
            matches!(
                manifest.evaluate(&deny_request),
                ManifestVerdict::Denied(DenyReason::ExplicitRule {
                    entry_index,
                    ..
                }) if entry_index == deny_idx_u32
            ),
            "capability manifest {} did not enforce deny entry {}",
            manifest_path.display(),
            deny_idx
        );
    }
    Ok(())
}
