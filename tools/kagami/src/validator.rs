use std::path::{Path, PathBuf};

use color_eyre::Result;
use path_absolutize::Absolutize;
use swarm::AbsolutePath;

use super::*;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    /// Directory path to clone Iroha sources to. Only
    /// used in case when `kagami` is run as a separate
    /// binary. A temporary directory is created for this
    /// purpose if this option is not provided but cloning
    /// is still needed.
    #[clap(long)]
    clone_dir: Option<PathBuf>,
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let clone_dir = match self.clone_dir {
            Some(dir) => dir,
            None => tempfile::tempdir()
                .wrap_err("Failed to generate a tempdir for validator sources")?
                .into_path(),
        };
        let path = compute_validator_path(clone_dir.as_path())?;
        writer
            .write_all(&construct_validator(path)?)
            .wrap_err("Failed to write wasm validator into the buffer.")
    }
}

/// A function computing where the validator file should be stored depending on whether `kagami` is
/// run as a standalone binary or via cargo. This is determined based on whether
/// the `CARGO_MANIFEST_DIR` env variable is set.
pub fn compute_validator_path(out_dir: impl AsRef<Path>) -> Result<PathBuf> {
    std::env::var("CARGO_MANIFEST_DIR").map_or_else(
        |_| {
            let out_dir = AbsolutePath::try_from(PathBuf::from(out_dir.as_ref()).join(DIR_CLONE))?;
            swarm::shallow_git_clone(GIT_ORIGIN, GIT_REVISION, &out_dir)?;
            Ok(out_dir.to_path_buf().join("default_validator"))
        },
        |manifest_dir| Ok(Path::new(&manifest_dir).join("default_validator")),
    )
}

/// Variant of [`compute_validator_path()`] to be used via `kagami swarm` to avoid double repo
/// cloning if `swarm` subcommand has already done that.
pub fn compute_validator_path_with_build_dir(build_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let validator_path = build_dir
        .as_ref()
        .join("default_validator")
        .absolutize()
        .map(|abs_path| abs_path.to_path_buf())
        .wrap_err_with(|| {
            format!(
                "Failed to construct absolute path for: {}",
                build_dir.as_ref().display(),
            )
        });
    // Setting this so that [`Builder`](iroha_wasm_builder::Builder) doesn't pollute
    // the swarm output dir with a `target` remnant
    std::env::set_var(
        "IROHA_WASM_BUILDER_OUT_DIR",
        build_dir.as_ref().join("target"),
    );
    validator_path
}

pub fn construct_validator(relative_path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let wasm_blob = iroha_wasm_builder::Builder::new(relative_path.as_ref())
        .build()?
        .optimize()?
        .into_bytes()?;

    Ok(wasm_blob)
}
