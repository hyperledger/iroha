//! Provides macros used to get the version

use std::{env::set_var, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    // We default to upstream's latest hash (usually `iroha2-dev`)
    // to enable shallow cloning in swarm
    let repo = git2::Repository::open("../..")?;
    let sha = match repo.revparse_single("@{u}") {
        Ok(rev) => rev.id(),
        Err(_) => repo.revparse_single("HEAD")?.id(),
    };
    set_var("VERGEN_GIT_SHA", sha.to_string());
    vergen::EmitBuilder::builder().git_sha(false).emit()?;
    Ok(())
}
