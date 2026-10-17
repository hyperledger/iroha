//! Audit convenience commands for the CLI (debug endpoints).
use crate::{
    Run, RunContext,
    json_utils::{json_array, json_object, json_value},
};
use clap::ArgAction;
use eyre::Result;
use fastpq_prover::{OperationKind, RowUsage, StateTransition, TransitionBatch, build_trace};
use iroha::client::Client;
use iroha::data_model::{
    block::consensus::{ExecKv, ExecWitness},
    fastpq::TransferTranscriptBundle,
};
use iroha_core::fastpq;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Fetch current execution witness snapshot from Torii debug endpoints
    Witness(WitnessArgs),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Witness(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct WitnessArgs {
    /// Fetch Norito-encoded binary instead of JSON
    #[arg(long)]
    binary: bool,
    /// Output path for binary; if omitted with --binary, hex is printed to stdout
    #[arg(long, value_name = "PATH")]
    out: Option<std::path::PathBuf>,
    /// Decode a Norito-encoded `ExecWitness` from a file and print with human-readable keys
    #[arg(long, value_name = "PATH", conflicts_with = "binary")]
    decode: Option<std::path::PathBuf>,
    /// Filter decoded entries by key namespace prefix (comma-separated).
    /// Shorthand groups supported:
    /// - roles => [role, role.binding, perm.account, perm.role]
    /// - assets => [asset, `asset_def.total`]
    /// - `all_assets` => [asset, `asset_def.total`, `asset_def.detail`]
    /// - metadata => [account.detail, domain.detail, nft.detail, `asset_def.detail`]
    /// - `all_meta` => [account.detail, domain.detail, nft.detail, `asset_def.detail`] (alias of metadata)
    /// - perm | perms | permissions => [perm.account, perm.role]
    ///   Examples: "assets,metadata", "roles", "account.detail,domain.detail".
    ///   Applied only with --decode; prefixes match the human-readable key labels.
    ///
    /// Matching on the identifier segment supports:
    /// - exact (e.g., `account.detail:sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV`)
    /// - partial substring (e.g., `account.detail:6cmzPVPX`)
    /// - glob wildcards `*` and `?` (e.g., `asset:rose#*#6cmz*`)
    /// - regex-like syntax `/.../` (treated as a glob pattern inside the slashes)
    #[arg(long, value_name = "PREFIXES", requires = "decode")]
    filter: Option<String>,
    /// Include FASTPQ transition batches recorded in the witness when decoding (enabled by default).
    #[arg(
        long,
        action = ArgAction::SetTrue,
        default_value_t = true,
        overrides_with = "no_fastpq_batches"
    )]
    fastpq_batches: bool,
    /// Disable FASTPQ batches to shrink the decoded output.
    #[arg(
        long = "no-fastpq-batches",
        action = ArgAction::SetTrue,
        overrides_with = "fastpq_batches"
    )]
    no_fastpq_batches: bool,
    /// Expected FASTPQ parameter set name; errors if batches use a different value.
    #[arg(
        long,
        value_name = "NAME",
        default_value_t = fastpq::FASTPQ_CANONICAL_PARAMETER_SET.to_string()
    )]
    fastpq_parameter: String,
}
impl Run for WitnessArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        if let Some(path) = &self.decode {
            return self.run_decode(context, path);
        }
        if self.binary {
            return self.run_binary(context, &client);
        }
        Self::run_json(context, &client)
    }
}
#[derive(Clone)]
struct FilterSpec {
    prefix: String,
    arg: Option<String>,
}
impl WitnessArgs {
    fn include_fastpq_batches(&self) -> bool {
        self.fastpq_batches && !self.no_fastpq_batches
    }
    fn run_decode<C: RunContext>(&self, context: &mut C, path: &Path) -> Result<()> {
        let witness = Self::load_exec_witness(path)?;
        let specs = self.filter_specs();
        let reads = Self::collect_entries(&witness.reads, &specs)?;
        let writes = Self::collect_entries(&witness.writes, &specs)?;
        let transcripts = Self::collect_transcripts(&witness.fastpq_transcripts)?;
        let mut fields = vec![
            ("reads", json_array(reads)?),
            ("writes", json_array(writes)?),
            ("fastpq_transcripts", json_array(transcripts)?),
        ];
        if self.include_fastpq_batches() {
            let batches = self.collect_fastpq_batches(&witness)?;
            fields.push(("fastpq_batches", json_array(batches)?));
        }
        let payload = json_object(fields)?;
        context.print_data(&payload)?;
        Ok(())
    }
    fn run_binary<C: RunContext>(&self, context: &mut C, client: &Client) -> Result<()> {
        let bytes = client.get_debug_witness_norito()?;
        if let Some(path) = &self.out {
            fs::write(path, &bytes)?;
            context.println(format!("wrote {} bytes to {}", bytes.len(), path.display()))?;
        } else {
            context.println(hex::encode(bytes))?;
        }
        Ok(())
    }
    fn run_json<C: RunContext>(context: &mut C, client: &Client) -> Result<()> {
        let v = client.get_debug_witness_json()?;
        context.print_data(&v)?;
        Ok(())
    }
    fn load_exec_witness(path: &Path) -> Result<ExecWitness> {
        let bytes = fs::read(path)?;
        let mut slice: &[u8] = &bytes;
        norito::codec::Decode::decode(&mut slice).map_err(|e| eyre::eyre!("decode witness: {e}"))
    }
    fn collect_entries(
        entries: &[ExecKv],
        specs: &[FilterSpec],
    ) -> Result<Vec<norito::json::Value>> {
        let mut out = Vec::new();
        for kv in entries {
            let label = Self::pretty_key_label(&kv.key);
            if !Self::label_allowed(&label, specs) {
                continue;
            }
            let value = Self::decode_value_json(&kv.value)?;
            out.push(json_object(vec![
                ("key", json_value(&label)?),
                ("value", value),
            ])?);
        }
        Ok(out)
    }
    fn collect_transcripts(
        transcripts: &[TransferTranscriptBundle],
    ) -> Result<Vec<norito::json::Value>> {
        let mut out = Vec::with_capacity(transcripts.len());
        for bundle in transcripts {
            let entry_hex = format!("0x{}", hex::encode(bundle.entry_hash.as_ref()));
            let transcripts_json = norito::json::to_value(&bundle.transcripts)
                .map_err(|err| eyre::eyre!("serialize transcripts: {err}"))?;
            out.push(json_object(vec![
                ("entry_hash", json_value(&entry_hex)?),
                ("transcripts", transcripts_json),
            ])?);
        }
        Ok(out)
    }
    fn collect_fastpq_batches(&self, witness: &ExecWitness) -> Result<Vec<norito::json::Value>> {
        let batches = fastpq::batches_from_exec_witness(witness)?;
        if !self.fastpq_parameter.is_empty() {
            for batch in &batches {
                if batch.parameter != self.fastpq_parameter {
                    return Err(eyre::eyre!(
                        "FASTPQ batch parameter `{}` does not match expected `{}`",
                        batch.parameter,
                        self.fastpq_parameter
                    ));
                }
            }
        }
        batches.iter().map(Self::transition_batch_to_json).collect()
    }
    fn transition_batch_to_json(batch: &TransitionBatch) -> Result<norito::json::Value> {
        let trace = build_trace(batch).map_err(|err| eyre::eyre!("build FASTPQ trace: {err}"))?;
        let transitions = batch
            .transitions
            .iter()
            .map(Self::transition_json)
            .collect::<Result<Vec<_>>>()?;
        let mut fields = vec![
            ("parameter", json_value(&batch.parameter)?),
            (
                "public_inputs",
                Self::public_inputs_json(&batch.public_inputs)?,
            ),
            ("transitions", json_array(transitions)?),
            ("metadata", Self::metadata_json(&batch.metadata)?),
            ("row_usage", row_usage_json(trace.row_usage)?),
        ];
        if let Some(entry_hash) = batch.metadata.get(fastpq::ENTRY_HASH_METADATA_KEY) {
            fields.push(("entry_hash", json_value(&Self::hex(entry_hash))?));
        }
        json_object(fields)
    }
    fn metadata_json(metadata: &BTreeMap<String, Vec<u8>>) -> Result<norito::json::Value> {
        let entries = metadata
            .iter()
            .map(|(key, value)| Ok((key.clone(), json_value(&Self::hex(value))?)))
            .collect::<Result<Vec<_>>>()?;
        json_object(entries)
    }
    fn transition_json(transition: &StateTransition) -> Result<norito::json::Value> {
        json_object(vec![
            ("key_hex", json_value(&Self::hex(&transition.key))?),
            (
                "pre_value_hex",
                json_value(&Self::hex(&transition.pre_value))?,
            ),
            (
                "post_value_hex",
                json_value(&Self::hex(&transition.post_value))?,
            ),
            ("operation", Self::operation_json(&transition.operation)?),
        ])
    }
    fn public_inputs_json(inputs: &fastpq_prover::PublicInputs) -> Result<norito::json::Value> {
        json_object(vec![
            ("dsid_hex", json_value(&Self::hex(&inputs.dsid))?),
            ("slot", json_value(&inputs.slot)?),
            ("old_root_hex", json_value(&Self::hex(&inputs.old_root))?),
            ("new_root_hex", json_value(&Self::hex(&inputs.new_root))?),
            ("perm_root_hex", json_value(&Self::hex(&inputs.perm_root))?),
            (
                "tx_set_hash_hex",
                json_value(&Self::hex(&inputs.tx_set_hash))?,
            ),
        ])
    }
    fn operation_json(operation: &OperationKind) -> Result<norito::json::Value> {
        json_value(operation)
    }
    fn hex(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }
    fn decode_value_json(bytes: &[u8]) -> Result<norito::json::Value> {
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => {
                if let Ok(v) = norito::json::from_str::<norito::json::Value>(&s) {
                    Ok(v)
                } else {
                    Ok(norito::json::Value::String(s))
                }
            }
            Err(_) => json_object(vec![("raw_hex", json_value(&hex::encode(bytes))?)]),
        }
    }
    fn pretty_key_label(key: &[u8]) -> String {
        if key.is_empty() {
            return format!("hex:{}", hex::encode(key));
        }
        let tag = key[0];
        let rest = &key[1..];
        let us = 0x1F_u8;
        let split_once = |s: &[u8]| -> Option<(String, String)> {
            let pos = s.iter().position(|b| *b == us)?;
            let (a, b) = s.split_at(pos);
            let b = &b[1..];
            Some((
                String::from_utf8(a.to_vec()).ok()?,
                String::from_utf8(b.to_vec()).ok()?,
            ))
        };
        match tag {
            0xA1 => split_once(rest)
                .map(|(acc, name)| format!("account.detail:{acc}:{name}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            0xA2 => split_once(rest)
                .map(|(dom, name)| format!("domain.detail:{dom}:{name}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            0xA3 => split_once(rest)
                .map(|(nft, name)| format!("nft.detail:{nft}:{name}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            0xA4 => split_once(rest)
                .map(|(ad, name)| format!("asset_def.detail:{ad}:{name}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            0xB1 => String::from_utf8(rest.to_vec())
                .map(|id| format!("asset:{id}"))
                .unwrap_or_else(|_| format!("hex:{}", hex::encode(key))),
            0xB2 => String::from_utf8(rest.to_vec())
                .map(|id| format!("asset_def.total:{id}"))
                .unwrap_or_else(|_| format!("hex:{}", hex::encode(key))),
            0xC1 => split_once(rest)
                .map(|(acc, role)| format!("role.binding:{acc}:{role}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            0xC2 => String::from_utf8(rest.to_vec())
                .map(|role| format!("role:{role}"))
                .unwrap_or_else(|_| format!("hex:{}", hex::encode(key))),
            0xC3 => split_once(rest)
                .map(|(acc, perm)| format!("perm.account:{acc}:{perm}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            0xC4 => split_once(rest)
                .map(|(role, perm)| format!("perm.role:{role}:{perm}"))
                .unwrap_or_else(|| format!("hex:{}", hex::encode(key))),
            _ => format!("hex:{}", hex::encode(key)),
        }
    }
    fn filter_specs(&self) -> Vec<FilterSpec> {
        self.filter
            .as_ref()
            .map_or_else(Vec::new, |s| expand_filter_specs(s))
    }
    fn label_allowed(label: &str, specs: &[FilterSpec]) -> bool {
        if specs.is_empty() {
            return true;
        }
        specs.iter().any(|fs| {
            if !label.starts_with(&fs.prefix) {
                return false;
            }
            let Some(arg) = &fs.arg else {
                return true;
            };
            if label.len() <= fs.prefix.len()
                || &label.as_bytes()[fs.prefix.len()..fs.prefix.len() + 1] != b":"
            {
                return false;
            }
            let after_prefix = &label[(fs.prefix.len() + 1)..];
            let seg_end = after_prefix.find(':').unwrap_or(after_prefix.len());
            let first_seg = &after_prefix[..seg_end];
            if arg.len() >= 2 && arg.starts_with('/') && arg.ends_with('/') {
                glob_match(&arg[1..arg.len() - 1], first_seg)
            } else if arg.contains('*') || arg.contains('?') {
                glob_match(arg, first_seg)
            } else {
                first_seg == arg || first_seg.contains(arg)
            }
        })
    }
}
fn expand_prefixes(spec: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in spec.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        match token.to_ascii_lowercase().as_str() {
            "roles" => out.extend(
                ["role", "role.binding", "perm.account", "perm.role"]
                    .iter()
                    .map(ToString::to_string),
            ),
            "assets" => out.extend(["asset", "asset_def.total"].iter().map(ToString::to_string)),
            "all_assets" | "allasset" | "all-asset" | "assets_all" => out.extend(
                ["asset", "asset_def.total", "asset_def.detail"]
                    .iter()
                    .map(ToString::to_string),
            ),
            "metadata" | "all_meta" | "allmeta" | "all-metadata" | "metadata_all" => out.extend(
                [
                    "account.detail",
                    "domain.detail",
                    "nft.detail",
                    "asset_def.detail",
                ]
                .iter()
                .map(ToString::to_string),
            ),
            "perm" | "perms" | "permissions" => {
                out.extend(
                    ["perm.account", "perm.role"]
                        .iter()
                        .map(ToString::to_string),
                );
            }
            _ => out.push(token.to_string()),
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}
fn expand_filter_specs(spec: &str) -> Vec<FilterSpec> {
    let expanded = expand_prefixes(spec);
    let mut out: Vec<FilterSpec> = Vec::new();
    for token in expanded {
        if let Some((prefix, arg)) = token.split_once(':') {
            out.push(FilterSpec {
                prefix: prefix.to_string(),
                arg: Some(arg.to_string()),
            });
        } else {
            out.push(FilterSpec {
                prefix: token,
                arg: None,
            });
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|fs| {
        seen.insert(format!(
            "{}\x1F{}",
            fs.prefix,
            fs.arg.clone().unwrap_or_default()
        ))
    });
    out
}
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();
    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
            continue;
        }
        if pi < pat.len() && pat[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
            continue;
        }
        if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
            if ti > txt.len() {
                return false;
            }
            continue;
        }
        return false;
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}
fn row_usage_json(usage: RowUsage) -> Result<norito::json::Value> {
    #[allow(clippy::cast_precision_loss)]
    let ratio = if usage.total_rows == 0 {
        0.0
    } else {
        (usage.transfer_rows as f64) / (usage.total_rows as f64)
    };
    json_object(vec![
        ("total_rows", json_value(&usage.total_rows)?),
        ("transfer_rows", json_value(&usage.transfer_rows)?),
        ("non_transfer_rows", json_value(&usage.non_transfer_rows())?),
        ("mint_rows", json_value(&usage.mint_rows)?),
        ("burn_rows", json_value(&usage.burn_rows)?),
        ("role_grant_rows", json_value(&usage.role_grant_rows)?),
        ("role_revoke_rows", json_value(&usage.role_revoke_rows)?),
        ("meta_set_rows", json_value(&usage.meta_set_rows)?),
        ("permission_rows", json_value(&usage.permission_rows)?),
        ("transfer_ratio", json_value(&ratio)?),
    ])
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn operation_json_preserves_unit_selectors() {
        for (operation, kind) in [
            (OperationKind::Transfer, "Transfer"),
            (OperationKind::Mint, "Mint"),
            (OperationKind::Burn, "Burn"),
            (OperationKind::MetaSet, "MetaSet"),
        ] {
            let value = WitnessArgs::operation_json(&operation).expect("serialize unit selector");
            assert_eq!(
                norito::json::from_value::<OperationKind>(value.clone())
                    .expect("decode unit selector"),
                operation,
            );
            assert_eq!(value, norito::json!({ "kind": kind, "payload": null }),);
        }
    }

    #[test]
    fn operation_json_preserves_permission_payloads() {
        let role_id = [0x11; 32];
        let permission_id = [0x22; 32];
        let epoch = u64::MAX;
        for (operation, kind) in [
            (
                OperationKind::RoleGrant {
                    role_id,
                    permission_id,
                    epoch,
                },
                "RoleGrant",
            ),
            (
                OperationKind::RoleRevoke {
                    role_id,
                    permission_id,
                    epoch,
                },
                "RoleRevoke",
            ),
        ] {
            let value =
                WitnessArgs::operation_json(&operation).expect("serialize permission selector");
            assert_eq!(
                norito::json::from_value::<OperationKind>(value.clone())
                    .expect("decode permission selector"),
                operation,
            );
            assert_eq!(
                value,
                norito::json!({
                    "kind": kind,
                    "payload": {
                        "role_id": role_id,
                        "permission_id": permission_id,
                        "epoch": epoch,
                    },
                }),
            );
        }
    }

    #[test]
    fn row_usage_json_preserves_the_exact_v1_ratio() {
        let value = row_usage_json(RowUsage {
            total_rows: 3,
            transfer_rows: 1,
            meta_set_rows: 2,
            ..RowUsage::default()
        })
        .expect("serialize row usage");
        assert_eq!(
            value["transfer_ratio"].as_f64(),
            Some(1.0 / 3.0),
            "release evidence must not round away the count-derived ratio"
        );
    }
    #[test]
    fn row_usage_json_preserves_every_operation_and_permission_count() {
        let value = row_usage_json(RowUsage {
            total_rows: 21,
            transfer_rows: 1,
            mint_rows: 2,
            burn_rows: 3,
            role_grant_rows: 4,
            role_revoke_rows: 5,
            meta_set_rows: 6,
            permission_rows: 9,
        })
        .expect("serialize all row counts");
        for (field, expected) in [
            ("total_rows", 21),
            ("transfer_rows", 1),
            ("non_transfer_rows", 20),
            ("mint_rows", 2),
            ("burn_rows", 3),
            ("role_grant_rows", 4),
            ("role_revoke_rows", 5),
            ("meta_set_rows", 6),
            ("permission_rows", 9),
        ] {
            assert_eq!(value[field].as_u64(), Some(expected), "{field}");
        }
    }
    #[derive(Parser, Debug)]
    #[command(no_binary_name = true)]
    struct Wrapper {
        #[command(flatten)]
        args: WitnessArgs,
    }
    fn parse_args(args: &[&str]) -> WitnessArgs {
        Wrapper::parse_from(args).args
    }
    #[test]
    fn fastpq_batches_enabled_by_default() {
        let args = parse_args(&[]);
        assert!(args.include_fastpq_batches());
    }
    #[test]
    fn fastpq_batches_can_be_disabled() {
        let args = parse_args(&["--no-fastpq-batches"]);
        assert!(!args.include_fastpq_batches());
    }
    #[test]
    fn fastpq_batches_flag_reenables_output() {
        let args = parse_args(&["--no-fastpq-batches", "--fastpq-batches"]);
        assert!(args.include_fastpq_batches());
    }
}
