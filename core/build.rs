use anyhow::Result;
use vergen::ShaKind;

fn main() -> Result<()> {
    let mut config = vergen::Config::default();
    *config.git_mut().sha_kind_mut() = ShaKind::Short;
    vergen::vergen(config)
}
