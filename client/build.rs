//! Build script to extract git hash of Iroha build

use color_eyre::{
    eyre::{eyre, WrapErr},
    Result,
};

fn main() -> Result<()> {
    vergen::EmitBuilder::builder()
        .git_sha(true)
        .emit()
        .map_err(|err| eyre!(Box::new(err)))
        .wrap_err("Failed to extract git hash")
}
