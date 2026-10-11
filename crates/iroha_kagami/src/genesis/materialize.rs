//! Explicit materialization of non-signable genesis source templates.

use crate::{Outcome, RunArgs, tui};
use clap::Parser;
use color_eyre::eyre::WrapErr as _;
use iroha_genesis::{GenesisSourceTemplate, validate_genesis_manifest_json};
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

/// Materialize a `.template.json` source with its explicit NPoS XOR selection.
#[derive(Clone, Debug, Parser)]
pub struct Args {
    /// Incomplete genesis source file; the name must end in `.template.json`.
    template_file: PathBuf,
    /// Explicit canonical XOR definition committed by an NPoS source template.
    #[arg(long, value_name = "ASSET_DEFINITION_ID")]
    xor_asset_definition_id: Option<iroha_data_model::asset::AssetDefinitionId>,
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        tui::status("Materializing genesis source template");
        let manifest = GenesisSourceTemplate::from_path(&self.template_file)?
            .materialize(self.xor_asset_definition_id)
            .wrap_err("materialize complete genesis manifest")?;
        super::ensure_genesis_schedule_matches_consensus(&manifest)?;
        let has_topology = manifest
            .transactions()
            .iter()
            .any(|transaction| !transaction.topology().is_empty());
        if has_topology {
            super::ensure_genesis_topology_is_generation_zero(&manifest)?;
        }
        let mut json = norito::json::to_json_pretty(&manifest)?;
        json.push('\n');
        validate_genesis_manifest_json(json.as_bytes())
            .wrap_err("materialized genesis exceeds fixed resource bounds")?;
        writer
            .write_all(json.as_bytes())
            .wrap_err("write materialized genesis manifest")?;
        tui::success("Genesis source template materialized");
        Ok(())
    }
}
