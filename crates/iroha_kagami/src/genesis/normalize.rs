use crate::{Outcome, RunArgs, tui};
use clap::{Parser, ValueEnum};
use color_eyre::eyre::eyre;
use iroha_genesis::{NormalizedGenesis, RawGenesisTransaction};
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};
/// Show the fully expanded genesis block (after injections and ordering).
#[derive(Clone, Debug, Parser)]
pub struct Args {
    /// Path to genesis json file
    genesis_file: PathBuf,
    /// Output format (`json` for structured output, `text` for a compact summary)
    #[clap(long, value_enum, default_value = "json")]
    format: OutputFormat,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Json,
    Text,
}
impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        tui::status("Normalizing genesis manifest");
        let manifest = RawGenesisTransaction::from_path(&self.genesis_file)?;
        let normalized = manifest.normalize()?;
        match self.format {
            OutputFormat::Json => render_json(&normalized, writer)?,
            OutputFormat::Text => render_text(&normalized, writer)?,
        }
        tui::success("Genesis manifest normalized");
        Ok(())
    }
}
fn render_json<T: Write>(
    normalized: &NormalizedGenesis,
    writer: &mut BufWriter<T>,
) -> color_eyre::Result<()> {
    writeln!(writer, "{{")?;
    write!(writer, "  \"chain\": ")?;
    write_json_value(writer, &normalized.chain)?;
    writeln!(writer, ",")?;
    writeln!(
        writer,
        "  \"chain_discriminant\": {},",
        normalized.chain_discriminant
    )?;
    write!(writer, "  \"executor\": ")?;
    if let Some(path) = &normalized.executor {
        write_json_value(writer, &path.as_path().display().to_string())?;
    } else {
        write!(writer, "null")?;
    }
    writeln!(writer, ",")?;
    write!(writer, "  \"ivm_dir\": ")?;
    write_json_value(writer, &normalized.ivm_dir.display().to_string())?;
    writeln!(writer, ",")?;
    write!(writer, "  \"consensus_mode\": ")?;
    write_json_value(writer, &normalized.consensus_mode)?;
    writeln!(writer, ",")?;
    writeln!(
        writer,
        "  \"wire_protocol_version\": {},",
        normalized.wire_protocol_version
    )?;
    write!(writer, "  \"consensus_fingerprint\": ")?;
    write_json_value(writer, &normalized.consensus_fingerprint)?;
    writeln!(writer, ",")?;
    write!(writer, "  \"sumeragi_context\": ")?;
    write_json_value(writer, &normalized.sumeragi_context)?;
    writeln!(writer, ",")?;
    write!(writer, "  \"crypto_admission_policy\": ")?;
    write_json_value(writer, &normalized.crypto_admission_policy)?;
    writeln!(writer, ",")?;
    writeln!(writer, "  \"transactions\": [")?;
    for (tx_idx, instructions) in normalized.transactions.iter().enumerate() {
        writeln!(writer, "    {{")?;
        writeln!(writer, "      \"index\": {tx_idx},")?;
        writeln!(writer, "      \"instructions\": [")?;
        for (instruction_idx, instruction) in instructions.iter().enumerate() {
            let value = iroha_genesis::genesis_instructions_json::instruction_value(instruction);
            write!(writer, "        ")?;
            write_json_value(writer, &value)?;
            if instruction_idx + 1 == instructions.len() {
                writeln!(writer)?;
            } else {
                writeln!(writer, ",")?;
            }
        }
        writeln!(writer, "      ]")?;
        if tx_idx + 1 == normalized.transactions.len() {
            writeln!(writer, "    }}")?;
        } else {
            writeln!(writer, "    }},")?;
        }
    }
    writeln!(writer, "  ]")?;
    writeln!(writer, "}}")?;
    Ok(())
}
fn write_json_value<T: norito::json::JsonSerialize + ?Sized, W: Write>(
    writer: &mut BufWriter<W>,
    value: &T,
) -> color_eyre::Result<()> {
    let json = norito::json::to_json(value)
        .map_err(|error| eyre!("serialize normalized genesis value: {error}"))?;
    writer.write_all(json.as_bytes())?;
    Ok(())
}
fn render_text<T: Write>(
    normalized: &NormalizedGenesis,
    writer: &mut BufWriter<T>,
) -> color_eyre::Result<()> {
    writeln!(writer, "chain: {}", normalized.chain)?;
    writeln!(
        writer,
        "executor: {}",
        normalized
            .executor
            .as_ref()
            .map_or_else(|| "none".into(), |p| p.as_path().display().to_string())
    )?;
    writeln!(writer, "ivm_dir: {}", normalized.ivm_dir.display())?;
    writeln!(writer, "consensus_mode: {:?}", normalized.consensus_mode)?;
    writeln!(
        writer,
        "wire_protocol_version: {:?}",
        normalized.wire_protocol_version
    )?;
    writeln!(
        writer,
        "consensus_fingerprint: {}",
        normalized.consensus_fingerprint
    )?;
    writeln!(
        writer,
        "crypto_admission_policy.allowed_algorithms: {:?}",
        normalized.crypto_admission_policy.allowed_algorithms()
    )?;
    for (tx_idx, instructions) in normalized.transactions.iter().enumerate() {
        writeln!(
            writer,
            "tx[{tx_idx}] ({} instructions):",
            instructions.len()
        )?;
        for (instr_idx, instr) in instructions.iter().enumerate() {
            let value = iroha_genesis::genesis_instructions_json::instruction_value(instr);
            let rendered = norito::json::to_json(&value)
                .unwrap_or_else(|err| format!("\"<render error: {err}>\""));
            writeln!(writer, "  [{instr_idx}] {rendered}")?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::parameter::system::SumeragiConsensusMode;
    use iroha_genesis::GenesisBuilder;
    use iroha_model_base::chain::ChainId;
    use std::{fs, path::PathBuf};
    use tempfile::NamedTempFile;
    fn minimal_genesis() -> NamedTempFile {
        let genesis_file = NamedTempFile::new().expect("create temp genesis");
        let manifest = super::super::complete_test_genesis_builder(
            GenesisBuilder::new_without_executor(
                ChainId::from("test-chain"),
                PathBuf::from("."),
                iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                    iroha_crypto::Algorithm::Secp256k1,
                    iroha_crypto::Algorithm::BlsNormal,
                ])
                .expect("explicit canonical genesis producer policy"),
            )
            .with_staking_policy(crate::genesis::test_staking_policy())
            .expect("explicit fixture staking policy"),
        )
        .build_raw()
        .expect("complete normalize test genesis")
        .with_consensus_mode(SumeragiConsensusMode::Permissioned);
        let genesis_json = norito::json::to_json_pretty(&manifest).expect("serialize genesis");
        fs::write(genesis_file.path(), genesis_json).expect("write genesis json");
        genesis_file
    }
    #[test]
    fn emits_json() {
        let genesis = minimal_genesis();
        let args = Args {
            genesis_file: genesis.path().to_path_buf(),
            format: OutputFormat::Json,
        };
        let mut sink = BufWriter::new(Vec::new());
        args.run(&mut sink).expect("normalize json");
        let out = String::from_utf8(sink.into_inner().expect("buf")).expect("utf8");
        let _: norito::json::Value =
            norito::json::from_str(&out).expect("normalized JSON must be valid");
        assert!(
            out.contains("consensus_fingerprint"),
            "output should include metadata"
        );
    }
    #[test]
    fn emits_text_summary() {
        let genesis = minimal_genesis();
        let args = Args {
            genesis_file: genesis.path().to_path_buf(),
            format: OutputFormat::Text,
        };
        let mut sink = BufWriter::new(Vec::new());
        args.run(&mut sink).expect("normalize text");
        let out = String::from_utf8(sink.into_inner().expect("buf")).expect("utf8");
        assert!(out.contains("tx[0]"), "expected transaction listing");
    }
}
