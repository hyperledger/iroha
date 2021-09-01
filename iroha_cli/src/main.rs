//! Iroha peer command line

use iroha::{prelude::AllowAll, Arguments, Iroha};
use iroha_error::Reporter;
use iroha_permissions_validators::public_blockchain::default_permissions;
use structopt::StructOpt;

#[tokio::main]
#[allow(clippy::unwrap_used)]
async fn main() -> Result<(), Reporter> {
    iroha_error::install_panic_reporter();

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
