use crate::{Outcome, RunArgs, tui};
use clap::Parser;
use color_eyre::eyre::{WrapErr as _, eyre};
use iroha_data_model::account::address::ChainDiscriminantGuard;
use iroha_genesis::{
    ManifestCrypto, RawGenesisTransaction, genesis_instructions_json, read_genesis_manifest_bytes,
};
use iroha_model_base::name::Name;
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};
/// Validate a genesis JSON file and report offending fields (e.g., invalid `Name`s)
#[derive(Clone, Debug, Parser)]
pub struct Args {
    /// Path to genesis json file
    genesis_file: PathBuf,
}
struct Offense {
    path: String,
    message: String,
}
impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        tui::status("Validating genesis manifest");
        let bytes = read_genesis_manifest_bytes(&self.genesis_file)
            .wrap_err("read genesis manifest under fixed resource bounds")?;
        let manifest = RawGenesisTransaction::from_json_slice(&bytes)
            .wrap_err("genesis manifest failed structural validation")?;
        validate_consensus_manifest(&manifest)?;
        let chain_discriminant = manifest.chain_discriminant();
        drop(manifest);
        let json: norito::json::Value = norito::json::from_slice(&bytes)?;
        drop(bytes);
        let consensus_mode = json.get("consensus_mode");
        if consensus_mode.is_none() || consensus_mode.is_some_and(norito::json::Value::is_null) {
            return Err(eyre!(
                "genesis manifest missing consensus_mode; regenerate with `kagami genesis generate --consensus-mode <mode>`"
            ));
        }
        let offenses = collect_offenses_from_value(&json, Some(chain_discriminant));
        if offenses.is_empty() {
            writeln!(writer, "OK: no offending identifiers found")?;
            tui::success("Genesis manifest validated");
        } else {
            writeln!(writer, "Found {} offending field(s):", offenses.len())?;
            for off in offenses {
                writeln!(writer, "- {}: {}", off.path, off.message)?;
            }
            // Non-zero exit to integrate with CI or scripts
            tui::warn("Validation failed");
            color_eyre::eyre::bail!("genesis validation failed")
        }
        Ok(())
    }
}
fn validate_consensus_manifest(manifest: &RawGenesisTransaction) -> color_eyre::Result<()> {
    super::require_native_wire_protocol(manifest)?;
    super::ensure_genesis_schedule_matches_consensus(manifest)?;
    let has_topology = manifest
        .transactions()
        .iter()
        .any(|transaction| !transaction.topology().is_empty());
    if has_topology {
        super::ensure_genesis_topology_is_generation_zero(manifest)?;
    }
    Ok(())
}
fn collect_offenses_from_value(
    json: &norito::json::Value,
    chain_discriminant: Option<u16>,
) -> Vec<Offense> {
    let _chain_discriminant = chain_discriminant.map(ChainDiscriminantGuard::enter);
    let mut offenses: Vec<Offense> = Vec::new();
    // Validate top-level fields if present
    validate_parameters("/parameters", json.get("parameters"), &mut offenses);
    validate_instructions_array("/instructions", json.get("instructions"), &mut offenses);
    validate_crypto("/crypto", json.get("crypto"), &mut offenses);
    // Validate per-transaction fields
    if let Some(txs) = json.get("transactions").and_then(|v| v.as_array()) {
        for (i, tx) in txs.iter().enumerate() {
            validate_parameters(
                &format!("/transactions/{i}/parameters"),
                tx.get("parameters"),
                &mut offenses,
            );
            validate_instructions_array(
                &format!("/transactions/{i}/instructions"),
                tx.get("instructions"),
                &mut offenses,
            );
        }
    }
    offenses
}
fn validate_parameters(
    path: &str,
    params: Option<&norito::json::Value>,
    offenses: &mut Vec<Offense>,
) {
    let Some(params) = params else {
        return;
    };
    let Some(custom) = params.get("custom") else {
        return;
    };
    if let Some(map) = custom.as_object() {
        for key in map.keys() {
            if let Err(err) = key.parse::<Name>() {
                offenses.push(Offense {
                    path: format!("{path}/custom/{}", key),
                    message: format!("invalid Name: {}", err),
                });
            }
        }
    }
}
fn validate_crypto(path: &str, value: Option<&norito::json::Value>, offenses: &mut Vec<Offense>) {
    let Some(value) = value else {
        return;
    };
    match norito::json::value::from_value::<ManifestCrypto>(value.clone()) {
        Ok(crypto) => {
            if let Err(err) = crypto.validate() {
                offenses.push(Offense {
                    path: path.to_owned(),
                    message: err.to_string(),
                });
            }
        }
        Err(err) => offenses.push(Offense {
            path: path.to_owned(),
            message: format!("invalid crypto configuration: {err}"),
        }),
    }
}
fn validate_instructions_array(
    path: &str,
    maybe_instrs: Option<&norito::json::Value>,
    offenses: &mut Vec<Offense>,
) {
    let Some(instrs) = maybe_instrs else {
        return;
    };
    if !instrs.is_array() {
        return;
    }
    if let Err(err) = genesis_instructions_json::from_value(instrs) {
        offenses.push(Offense {
            path: path.to_owned(),
            message: format!("invalid instructions: {err}"),
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    };
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::chain::ChainId;
    use std::{fs, io::BufWriter, path::PathBuf};
    use tempfile::NamedTempFile;
    #[test]
    fn detects_invalid_custom_parameter_key() {
        let json = norito::json!({
            "chain": "0",
            "executor": "executor.to",
            "ivm_dir": ".",
            "transactions": [{
                "parameters": {
                    "custom": { "bad key": 10 }
                },
                "instructions": []
            }]
        });
        // Call internal validator directly to avoid filesystem use in tests
        let offenses = collect_offenses_from_value(&json, None);
        let out = offenses
            .into_iter()
            .map(|o| format!("{}: {}", o.path, o.message))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(out.contains("/transactions/0/parameters/custom/bad key"));
        assert!(out.contains("invalid Name"));
    }
    #[test]
    fn instruction_validation_respects_manifest_chain_discriminant() {
        let json = norito::json!({
            "transactions": [{
                "instructions": [{
                    "Mint": {
                        "Asset": {
                            "destination": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#testuﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                            "object": "13"
                        }
                    }
                }]
            }]
        });
        let offenses = collect_offenses_from_value(&json, Some(369));
        assert!(
            offenses.is_empty(),
            "Taira account literals must validate under the manifest chain discriminant"
        );
    }
    #[test]
    fn run_rejects_missing_consensus_mode() {
        let manifest = r#"{
            "chain": "0",
            "chain_discriminant": 1,
            "executor": null,
            "ivm_dir": ".",
            "transactions": [
                {}
            ]
        }"#;
        let temp = NamedTempFile::new().expect("create temp file");
        fs::write(temp.path(), manifest).expect("write manifest");
        let args = Args {
            genesis_file: temp.path().to_path_buf(),
        };
        let mut sink = BufWriter::new(Vec::<u8>::new());
        let err = args
            .run(&mut sink)
            .expect_err("missing consensus_mode should be rejected");
        assert!(
            format!("{err:#}").contains("consensus_mode"),
            "unexpected error: {err:#}"
        );
    }
    #[test]
    fn run_accepts_permissioned_consensus() {
        let manifest = super::super::complete_test_genesis_builder(
            GenesisBuilder::new_without_executor(ChainId::from("0"), PathBuf::from(".")),
        )
        .build_raw()
        .expect("complete permissioned validation fixture")
        .with_consensus_mode(SumeragiConsensusMode::Permissioned)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let manifest = norito::json::to_json_pretty(&manifest).expect("serialize manifest");
        let temp = NamedTempFile::new().expect("create temp file");
        fs::write(temp.path(), manifest).expect("write manifest");
        let args = Args {
            genesis_file: temp.path().to_path_buf(),
        };
        let mut sink = BufWriter::new(Vec::<u8>::new());
        args.run(&mut sink)
            .expect("permissioned consensus should be allowed");
    }
    #[test]
    fn consensus_validation_rejects_authority_mismatched_with_embedded_topology() {
        let topology = (0..4)
            .map(|_| {
                let key_pair = KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
                    .expect("generate topology key");
                let pop = bls_normal_pop_prove(key_pair.private_key())
                    .expect("generate topology proof of possession");
                GenesisTopologyEntry::new(
                    iroha_model_base::peer::PeerId::new(key_pair.public_key().clone()),
                    pop,
                )
            })
            .collect();
        let manifest = super::super::complete_test_genesis_builder(
            GenesisBuilder::new_without_executor(
                ChainId::from("mismatched-authority"),
                PathBuf::from("."),
            )
            .set_topology(topology),
        )
        .build_raw()
        .expect("complete mismatched validation fixture")
        .with_consensus_mode(SumeragiConsensusMode::Permissioned)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");

        let error = validate_consensus_manifest(&manifest)
            .expect_err("embedded topology must match the KAGEMUSHA authority exactly");
        assert!(
            error
                .to_string()
                .contains("does not match the exact genesis topology"),
            "unexpected error: {error:#}"
        );
    }
    #[test]
    fn run_accepts_canonical_npos() {
        let manifest = super::super::complete_test_genesis_builder(
            GenesisBuilder::new_without_executor(
                ChainId::from("npos-validate"),
                PathBuf::from("."),
            )
            .append_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            )),
        )
        .build_raw()
        .expect("complete NPoS validation fixture")
        .with_consensus_mode(SumeragiConsensusMode::Npos)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize manifest");
        let temp = NamedTempFile::new().expect("create temp file");
        fs::write(temp.path(), json).expect("write manifest");
        let args = Args {
            genesis_file: temp.path().to_path_buf(),
        };
        let mut sink = BufWriter::new(Vec::<u8>::new());
        args.run(&mut sink)
            .expect("canonical NPoS consensus should be accepted");
    }
}
