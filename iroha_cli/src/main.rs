//! Iroha peer command line

use color_eyre::Report;
use iroha::{prelude::AllowAll, Arguments, Iroha};
use iroha_permissions_validators::public_blockchain::default_permissions;
use structopt::StructOpt;

#[tokio::main]
#[allow(clippy::expect_used)]
async fn main() -> Result<(), Report> {
    color_eyre::install()?;

    <Iroha>::new(
        &Arguments::from_args(),
        default_permissions(),
        AllowAll.into(),
    )
    .await?
    .start()
    .await?;
    Ok(())
}
