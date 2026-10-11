//! Kotodama package build, test, publication and native deployment command runtime.
pub mod archive_fetch;
mod atomic_io;
mod bindgen;
pub mod cache;
mod cli;
mod command;
mod compiler;
mod compiler_identity;
/// File and package contract deployment with an explicitly resolved runtime context.
pub mod deployment_runtime;
pub mod generated_publication;
mod graph;
mod local_file;
mod lockfile;
pub mod manifest;
mod output;
mod package;
#[cfg(test)]
mod persistence_frame_fixture;
pub mod publication_runtime;
pub mod publish;
pub mod registry;
mod registry_cache;
mod resolver;
mod test_runner;
pub mod workspace;
/// Run the Musubi command-line interface.
///
/// Return the stable process exit status after writing routed command output.
#[must_use]
pub fn run() -> i32 {
    cli::run()
}
