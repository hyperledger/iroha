//! Build script to extract git hash of iroha build

fn main() -> eyre::Result<()> {
    let mut config = vergen::Config::default();

    *config.git_mut().branch_mut() = false;
    *config.git_mut().commit_timestamp_mut() = false;
    *config.git_mut().semver_mut() = false;

    vergen::vergen(config).map_err(|err| eyre::eyre!(Box::new(err)))
}
