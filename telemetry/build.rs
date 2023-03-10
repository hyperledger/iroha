//! Provides macros used to get the version

use eyre::{eyre, Result};

fn main() -> Result<()> {
    let mut config = vergen::Config::default();

    // TODO: This doesn't work, because safe.directory brought in by
    // `libgit2` is broken.  This is yet another reminder why relying
    // on a C library is usually the worst possible idea.
    *config.git_mut().sha_kind_mut() = vergen::ShaKind::Short;
    vergen::vergen(config).map_err(|err| eyre!(Box::new(err)))
}
