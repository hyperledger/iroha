//! Crate with helper tool to build smartcontracts, triggers and permission
//! validators for Iroha 2.
//!
//! See [`Builder`] for more details.

use std::{
    borrow::Cow,
    env,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{bail, eyre, Context as _, Result};

/// Current toolchain used to build smartcontracts
const TOOLCHAIN: &str = "+nightly-2022-12-22";

/// WASM Builder for smartcontracts, triggers and permission validators.
///
/// # Example
///
/// ```no_run
/// use iroha_wasm_builder::Builder;
/// use eyre::Result;
///
/// fn main() -> Result<()> {
///     let bytes = Builder::new("relative/path/to/smartcontract/")
///         .out_dir("path/to/out/dir") // Optional: Set output directory
///         .format() // Optional: Enable smartcontract formatting
///         .build()? // Run build
///         .optimize()? // Optimize WASM output
///         .into_bytes();
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
    /// Flag to enable smartcontract formatting
    format: bool,
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
            format: false,
        }
    }

    /// Set smartcontract build output directory.
    ///
    /// Default is `OUT_DIR` environment variable.
    pub fn out_dir<O>(mut self, out_dir: &'out_dir O) -> Self
    where
        O: AsRef<Path> + ?Sized,
    {
        self.out_dir = Some(out_dir.as_ref());
        self
    }

    /// Enable smartcontract formatting using `cargo fmt`.
    ///
    /// Disabled by default.
    pub fn format(mut self) -> Self {
        self.format = true;
        self
    }

    /// Check if smartcontract is valid without building it using `cargo check`.
    ///
    /// # Errors
    ///
    /// Can fail due to multiple reasons like invalid path, failed formatting,
    /// failed build, etc.
    pub fn check(self) -> Result<()> {
        self.into_internal()?.check()
    }

    /// Build smartcontract and get resulting wasm.
    ///
    /// # Errors
    ///
    /// Can fail due to multiple reasons like invalid path, failed formatting,
    /// failed build, etc.
    ///
    /// If you use this crate outside of *build-script* and does not provide
    /// [`out_dir`](Self::out_dir()) then this function will fail to find `OUT_DIR` variable
    /// and will return `Err`.
    pub fn build(self) -> Result<Output> {
        self.into_internal()?.build()
    }

    fn into_internal(self) -> Result<internal::Builder<'out_dir>> {
        Ok(internal::Builder {
            absolute_path: self.absolute_path()?,
            out_dir: self.out_dir.map_or_else(
                || -> Result<_> { Ok(Cow::Owned(Self::default_out_dir()?)) },
                |out_dir| Ok(Cow::Borrowed(out_dir)),
            )?,
            format: self.format,
        })
    }

    fn default_out_dir() -> Result<PathBuf> {
        env::var_os("OUT_DIR")
            .ok_or_else(|| eyre!("Expected `OUT_DIR` environment variable"))
            .map(Into::into)
    }

    fn absolute_path(&self) -> Result<PathBuf> {
        env::var("CARGO_MANIFEST_DIR")
            .wrap_err("Expected `CARGO_MANIFEST_DIR` environment variable")
            .and_then(|manifest_dir| {
                Path::new(&manifest_dir)
                    .join(self.path)
                    .canonicalize()
                    .wrap_err("Failed to canonicalize path")
            })
            .wrap_err_with(|| {
                format!(
                    "Failed to construct absolute path for: {}",
                    self.path.display(),
                )
            })
    }
}

mod internal {
    //! Internal implementation of [`Builder`](super::Builder).

    use std::{borrow::Cow, fs::File, io::Read};

    use super::*;

    #[derive(Debug)]
    pub struct Builder<'out_dir> {
        pub absolute_path: PathBuf,
        pub out_dir: Cow<'out_dir, Path>,
        pub format: bool,
    }

    impl Builder<'_> {
        pub fn check(self) -> Result<()> {
            self.maybe_format()?;

            self.check_smartcontract().wrap_err_with(|| {
                format!(
                    "Failed to check the smartcontract at path: {}",
                    self.absolute_path.display()
                )
            })
        }

        pub fn build(self) -> Result<Output> {
            self.maybe_format()?;

            self.build_smartcontract().wrap_err_with(|| {
                format!(
                    "Failed to build the smartcontract at path: {}",
                    self.absolute_path.display()
                )
            })
        }

        fn maybe_format(&self) -> Result<()> {
            if self.format {
                self.format_smartcontract().wrap_err_with(|| {
                    format!(
                        "Failed to format the smartcontract at path: {}",
                        self.absolute_path.display()
                    )
                })?;
            }
            Ok(())
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

        fn format_smartcontract(&self) -> Result<()> {
            let command_output = cargo_command()
                .current_dir(&self.absolute_path)
                .arg("fmt")
                .output()
                .wrap_err("Failed to run `cargo fmt`")?;

            check_command_output(&command_output, "cargo fmt")
        }

        fn check_smartcontract(&self) -> Result<()> {
            let command_output = cargo_command()
                .current_dir(&self.absolute_path)
                .arg("check")
                .args(Self::build_options())
                .output()
                .wrap_err("Failed to run `cargo check`")?;

            check_command_output(&command_output, "cargo check")
        }

        fn build_smartcontract(&self) -> Result<Output> {
            let out_dir = tempfile::tempdir().wrap_err("Failed to create temporary directory")?;

            let command_output = cargo_command()
                .current_dir(&self.absolute_path)
                .env("CARGO_TARGET_DIR", self.out_dir.as_ref())
                .arg("build")
                .args(Self::build_options())
                .args(["--out-dir", &out_dir.path().display().to_string()])
                .output()
                .wrap_err("Failed to run `cargo build`")?;

            check_command_output(&command_output, "cargo build")?;

            let mut wasm_file = Self::find_wasm_file(out_dir.path())?;
            let mut wasm_data = Vec::new();
            wasm_file
                .read_to_end(&mut wasm_data)
                .wrap_err("Failed to read data from the output wasm file")?;

            out_dir
                .close()
                .wrap_err("Failed to remove temporary directory")?;

            Ok(Output { bytes: wasm_data })
        }

        fn find_wasm_file(dir: &Path) -> Result<File> {
            std::fs::read_dir(dir)?
                .filter_map(Result::ok)
                .find_map(|entry| {
                    let path = entry.path();
                    (path.is_file() && path.extension().map_or(false, |ext| ext == "wasm"))
                        .then_some(path)
                })
                .map(File::open)
                .ok_or_else(|| eyre!("Failed to find wasm file in the output directory"))?
                .wrap_err("Failed to open wasm file")
        }
    }
}

/// Build output representing wasm binary.
#[derive(Debug, Clone)]
pub struct Output {
    bytes: Vec<u8>,
}

impl Output {
    /// Optimize wasm output.
    ///
    /// # Errors
    ///
    /// Fails if internal tool fails to optimize wasm binary.
    #[allow(clippy::unnecessary_wraps)]
    pub fn optimize(self) -> Result<Self> {
        // TODO: Implement optimization
        Ok(self)
    }

    /// Get reference to the underling bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume [`Output`] and get the underling bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

// TODO: Remove cargo invocation (#2152)
fn cargo_command() -> Command {
    let mut cargo = Command::new("cargo");
    cargo
        // Removing environment variable to avoid
        // `error: infinite recursion detected` when running `cargo lints`
        .env_remove("RUST_RECURSION_COUNT")
        // Removing environment variable to avoid
        // `error: `profiler_builtins` crate (required by compiler options) is not compatible with crate attribute `#![no_core]``
        // when running with `-C instrument-coverage`
        // TODO: Check if there are no problems with that
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args([
            TOOLCHAIN,
        ]);
    cargo
}

fn check_command_output(command_output: &std::process::Output, command_name: &str) -> Result<()> {
    if !command_output.status.success() {
        bail!(
            "`{}` returned non zero exit code ({}). Stderr:\n{}",
            command_name,
            command_output.status,
            String::from_utf8_lossy(&command_output.stderr)
        );
    }

    Ok(())
}
