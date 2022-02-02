//! Iroha peer command line

use color_eyre::Report;
use iroha_core::{prelude::AllowAll, Arguments, Iroha};
use iroha_permissions_validators::public_blockchain::default_permissions;
use structopt::StructOpt;

#[tokio::main]
async fn main() -> Result<(), Report> {
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
