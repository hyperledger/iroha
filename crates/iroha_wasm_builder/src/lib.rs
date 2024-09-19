//! Crate with helper tool to build smartcontracts (e.g. triggers and executors) for Iroha 2.
//!
//! See [`Builder`] for more details.

use std::{
    borrow::Cow,
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{bail, eyre, Context as _, Result};
use path_absolutize::Absolutize;

/// Current toolchain used to build smartcontracts
const TOOLCHAIN: &str = "+nightly-2024-09-09";

/// WASM Builder for smartcontracts (e.g. triggers and executors).
///
/// # Example
///
/// ```no_run
/// use eyre::Result;
/// use iroha_wasm_builder::Builder;
///
/// fn main() -> Result<()> {
///     let bytes = Builder::new("relative/path/to/smartcontract/")
///         .out_dir("path/to/out/dir") // Optional: Set output directory
///         .build()? // Run build
///         .optimize()? // Optimize WASM output
///         .into_bytes()?; // Get resulting WASM bytes
///
///     // ...
///
///     Ok(())
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct Builder<'path, 'out_dir> {
    /// Path to the smartcontract or to the directory of smartcontracts
    path: &'path Path,
    /// Build output directory
    out_dir: Option<&'out_dir Path>,
    /// Flag controlling whether to show output of the build process
    show_output: bool,
}

impl<'path, 'out_dir> Builder<'path, 'out_dir> {
    /// Initialize [`Builder`] with path to smartcontract.
    ///
    /// `relative_path` should be relative to `CARGO_MANIFEST_DIR`.
    pub fn new<P>(relative_path: &'path P) -> Self
    where
        P: AsRef<Path> + ?Sized,
    {
        Self {
            path: relative_path.as_ref(),
            out_dir: None,
            show_output: false,
        }
    }

    /// Set smartcontract build output directory.
    ///
    /// By default the output directory will be assigned either from `IROHA_WASM_BUILDER_OUT_DIR` or
    /// `OUT_DIR` environment variables, in this order.
    /// If neither is set, then the `target` directory will be used.
    pub fn out_dir<O>(mut self, out_dir: &'out_dir O) -> Self
    where
        O: AsRef<Path> + ?Sized,
    {
        self.out_dir = Some(out_dir.as_ref());
        self
    }

    /// Enable showing output of the build process.
    ///
    /// Disabled by default.
    pub fn show_output(mut self) -> Self {
        self.show_output = true;
        self
    }

    /// Apply `cargo check` to the smartcontract.
    ///
    /// # Errors
    ///
    /// Can fail due to multiple reasons like invalid path, failed build, etc.
    pub fn check(self) -> Result<()> {
        self.into_internal()?.check()
    }

    /// Build smartcontract and get resulting wasm.
    ///
    /// # Errors
    ///
    /// Can fail due to multiple reasons like invalid path, failed build, etc.
    ///
    /// Will also return error if ran on workspace and not on the concrete package.
    pub fn build(self) -> Result<Output> {
        self.into_internal()?.build()
    }

    fn into_internal(self) -> Result<internal::Builder<'out_dir>> {
        let abs_path = Self::absolute_path(self.path)?;
        Ok(internal::Builder {
            absolute_path: abs_path
                .canonicalize()
                .wrap_err_with(|| format!("Failed to canonicalize path: {}", abs_path.display()))?,
            out_dir: self.out_dir.map_or_else(
                || -> Result<_> { Ok(Cow::Owned(Self::default_out_dir()?)) },
                |out_dir| Ok(Cow::Borrowed(out_dir)),
            )?,
            show_output: self.show_output,
        })
    }

    fn default_out_dir() -> Result<PathBuf> {
        env::var_os("IROHA_WASM_BUILDER_OUT_DIR")
            .or_else(|| env::var_os("OUT_DIR"))
            .map(PathBuf::from)
            .map_or_else(
                || {
                    const PATH: &str = "target";
                    let abs_path = Self::absolute_path(PATH)?;
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .create(&abs_path)
                        .wrap_err_with(|| {
                            format!("Failed to create directory at path: {}", abs_path.display())
                        })?;
                    abs_path.canonicalize().wrap_err_with(|| {
                        format!("Failed to canonicalize path: {}", abs_path.display())
                    })
                },
                Ok,
            )
    }

    fn absolute_path(relative_path: impl AsRef<Path>) -> Result<PathBuf> {
        // TODO: replace with [std::path::absolute](https://doc.rust-lang.org/stable/std/path/fn.absolute.html)
        // when it's stabilized
        relative_path
            .as_ref()
            .absolutize()
            .map(|abs_path| abs_path.to_path_buf())
            .wrap_err_with(|| {
                format!(
                    "Failed to construct absolute path for: {}",
                    relative_path.as_ref().display(),
                )
            })
    }
}

mod internal {
    //! Internal implementation of [`Builder`](super::Builder).

    use std::{borrow::Cow, process::Stdio};

    use super::*;

    #[derive(Debug)]
    pub struct Builder<'out_dir> {
        pub absolute_path: PathBuf,
        pub out_dir: Cow<'out_dir, Path>,
        pub show_output: bool,
    }

    impl Builder<'_> {
        pub fn check(self) -> Result<()> {
            self.check_smartcontract().wrap_err_with(|| {
                format!(
                    "Failed to check the smartcontract at path: {}",
                    self.absolute_path.display()
                )
            })
        }

        pub fn build(self) -> Result<Output> {
            let absolute_path = self.absolute_path.clone();
            self.build_smartcontract().wrap_err_with(|| {
                format!(
                    "Failed to build the smartcontract at path: {}",
                    absolute_path.display()
                )
            })
        }

        fn build_options() -> impl Iterator<Item = &'static str> {
            [
                "--release",
                "-Z",
                "build-std",
                "-Z",
                "build-std-features=panic_immediate_abort",
                "-Z",
                "unstable-options",
                "--target",
                "wasm32-unknown-unknown",
            ]
            .into_iter()
        }

        fn get_base_command(&self, cmd: &'static str) -> std::process::Command {
            let mut command = cargo_command();
            command
                .current_dir(&self.absolute_path)
                .stderr(Stdio::inherit())
                .arg(cmd)
                .args(Self::build_options());

            command
        }

        fn check_smartcontract(&self) -> Result<()> {
            let command = &mut self.get_base_command("check");

            check_command(self.show_output, command, "cargo check")
        }

        fn build_smartcontract(self) -> Result<Output> {
            let package_name = self
                .retrieve_package_name()
                .wrap_err("Failed to retrieve package name")?;

            let full_out_dir = self.out_dir.join("wasm32-unknown-unknown/release/");
            let wasm_file = full_out_dir.join(package_name).with_extension("wasm");

            let previous_hash = if wasm_file.exists() {
                let hash = sha256::try_digest(wasm_file.as_path()).wrap_err_with(|| {
                    format!(
                        "Failed to compute sha256 digest of wasm file: {}",
                        wasm_file.display()
                    )
                })?;
                Some(hash)
            } else {
                None
            };

            check_command(
                self.show_output,
                self.get_base_command("build")
                    .env("CARGO_TARGET_DIR", self.out_dir.as_ref()),
                "cargo build",
            )?;

            Ok(Output {
                wasm_file,
                previous_hash,
            })
        }

        fn retrieve_package_name(&self) -> Result<String> {
            let manifest_output = cargo_command()
                .current_dir(&self.absolute_path)
                .arg("read-manifest")
                .output()
                .wrap_err("Failed to run `cargo read-manifest`")?;

            check_command_output(&manifest_output, "cargo read-manifest")?;

            let manifest = String::from_utf8(manifest_output.stdout)
                .wrap_err("Failed to convert `cargo read-manifest` output to string")?;

            manifest
                .parse::<serde_json::Value>()
                .wrap_err("Failed to parse `cargo read-manifest` output")?
                .get("name")
                .map(ToString::to_string)
                .map(|name| name.trim_matches('"').to_owned())
                .ok_or_else(|| {
                    eyre!("Failed to retrieve package name from `cargo read-manifest` output")
                })
        }
    }
}

/// Build output representing wasm binary.
#[derive(Debug)]
pub struct Output {
    /// Path to the non-optimized `.wasm` file.
    wasm_file: PathBuf,
    /// Hash of the `self.wasm_file` on previous iteration if there is some.
    previous_hash: Option<String>,
}

impl Output {
    /// Optimize wasm output.
    ///
    /// # Errors
    ///
    /// Fails if internal tool fails to optimize wasm binary.
    pub fn optimize(self) -> Result<Self> {
        let optimized_file = PathBuf::from(format!(
            "{parent}{separator}{file}_optimized.{ext}",
            parent = self
                .wasm_file
                .parent()
                .map_or_else(String::default, |p| p.display().to_string()),
            separator = std::path::MAIN_SEPARATOR,
            file = self
                .wasm_file
                .file_stem()
                .map_or_else(|| "output".into(), OsStr::to_string_lossy),
            ext = self
                .wasm_file
                .extension()
                .map_or_else(|| "wasm".into(), OsStr::to_string_lossy),
        ));

        let current_hash = sha256::try_digest(self.wasm_file.as_path()).wrap_err_with(|| {
            format!(
                "Failed to compute sha256 digest of wasm file: {}",
                self.wasm_file.display()
            )
        })?;

        match self.previous_hash {
            Some(previous_hash) if optimized_file.exists() && current_hash == previous_hash => {
                // Do nothing because original `.wasm` file wasn't changed
                // so `_optimized.wasm` should stay the same
            }
            _ => {
                let optimizer = wasm_opt::OptimizationOptions::new_optimize_for_size();
                optimizer.run(self.wasm_file, optimized_file.as_path())?;
            }
        }

        Ok(Self {
            wasm_file: optimized_file,
            previous_hash: Some(current_hash),
        })
    }

    /// Consume [`Output`] and get the underling bytes.
    ///
    /// # Errors
    ///
    /// Fails if the output file cannot be read.
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        use std::{fs::File, io::Read as _};

        let mut wasm_file = File::open(self.wasm_file)?;
        let mut wasm_data = Vec::new();
        wasm_file
            .read_to_end(&mut wasm_data)
            .wrap_err("Failed to read data from the output wasm file")?;

        Ok(wasm_data)
    }

    /// Get the file path of the underlying WASM
    #[must_use]
    pub fn wasm_file_path(&self) -> &PathBuf {
        &self.wasm_file
    }
}

// TODO: Remove cargo invocation (#2152)
#[allow(unreachable_code, unused)]
fn cargo_command() -> Command {
    const INSTRUMENT_COVERAGE_FLAG: &str = "instrument-coverage";
    for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if let Some(value) = env::var(var).ok() {
            if value.contains(INSTRUMENT_COVERAGE_FLAG) {
                eprintln!("WARNING: found `{INSTRUMENT_COVERAGE_FLAG}` rustc flag in `{var}` environment variable\n  \
                           This directly interferes with `-Z build-std` flag set by `iroha_wasm_builder`\n  \
                           See https://github.com/rust-lang/wg-cargo-std-aware/issues/68\n  \
                           Further execution of `cargo` will most probably fail with `could not find profiler-builtins` error");
            }
        }
    }

    let mut cargo = Command::new("cargo");
    cargo.arg(TOOLCHAIN);
    cargo
}

fn check_command_output(output: &std::process::Output, command_name: &str) -> Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "`{}` returned non zero exit code ({}). Stderr:\n{}",
            command_name,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn check_command(show_output: bool, command: &mut Command, command_name: &str) -> Result<()> {
    if show_output {
        let status = command
            .status()
            .wrap_err(format!("Failed to run `{command_name}`"))?;
        if status.success() {
            Ok(())
        } else {
            bail!(
                "`{command_name}` returned non zero exit code ({status}). See messages above for the probable error",
            );
        }
    } else {
        let output = command
            .output()
            .wrap_err(format!("Failed to run `{command_name}`"))?;
        check_command_output(&output, command_name)
    }
}
