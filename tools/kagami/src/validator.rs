use std::path::{Path, PathBuf};

use color_eyre::Result;
use path_absolutize::Absolutize;
use swarm::AbsolutePath;

use super::*;

#[derive(ClapArgs, Debug, Clone, Copy)]
pub struct Args;

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let path = compute_validator_path()?;
        writer
            .write_all(&construct_validator(path)?)
            .wrap_err("Failed to write wasm validator into the buffer.")
    }
}
pub fn compute_validator_path() -> Result<PathBuf> {
    // If `CARGO_MANIFEST_DIR` is set, it means the `kagami` binary is run via `cargo run`
    // command, otherwise it is called as a standalone
    std::env::var("CARGO_MANIFEST_DIR").map_or_else(
        |_| {
            let source_dir = tempfile::tempdir()
                .wrap_err("Failed to create temp dir for default runtime validator sources")?;
            let out_dir = AbsolutePath::try_from(source_dir.path().join(DIR_CLONE))?;
            swarm::shallow_git_clone(GIT_ORIGIN, GIT_REVISION, &out_dir)?;
            Ok(out_dir.to_path_buf().join("default_validator"))
        },
        |manifest_dir| Ok(Path::new(&manifest_dir).join("../../default_validator")),
    )
}

/// Variant of [`compute_validator_path()`] to be used via `kagami swarm` to avoid double repo
/// cloning if `swarm` subcommand has already done that.
pub fn compute_validator_path_with_swarm_dir(swarm_dir: impl AsRef<Path>) -> Result<PathBuf> {
    swarm_dir
        .as_ref()
        .join("../../default_validator")
        .absolutize()
        .map(|abs_path| abs_path.to_path_buf())
        .wrap_err_with(|| {
            format!(
                "Failed to construct absolute path for: {}",
                swarm_dir.as_ref().display(),
            )
        })
}

pub fn construct_validator(relative_path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let wasm_blob = iroha_wasm_builder::Builder::new(relative_path.as_ref())
        .build()?
        .optimize()?
        .into_bytes()?;

    Ok(wasm_blob)
}
