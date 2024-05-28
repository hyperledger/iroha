//! Build script to extract git hash of Iroha build

use eyre::{eyre, Result, WrapErr};

fn main() -> Result<()> {
    extract_git_hash()?;

    Ok(())
}

fn extract_git_hash() -> Result<()> {
    vergen::EmitBuilder::builder()
        .git_sha(true)
        .cargo_features()
        .emit()
        .map_err(|err| eyre!(Box::new(err)))
        .wrap_err("Failed to extract git hash")
}
