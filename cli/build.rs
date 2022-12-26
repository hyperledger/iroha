//! Build script to extract git hash of iroha build
use anyhow::Result;
use vergen::{vergen, Config};

fn main() -> Result<()> {
    let mut config = Config::default();
    *config.git_mut().branch_mut() = false;
    *config.git_mut().commit_timestamp_mut() = false;
    *config.git_mut().semver_mut() = false;
    vergen(config)
}
