//! Bounded execution resources shared by the real four-validator `SoraFS` tests.

use iroha_model_base::metadata::Metadata;
use std::future::Future;

use eyre::{Result, WrapErr as _, ensure};
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, FeeQuoteRequest},
    data_model::{prelude::*, transaction::FeePaymentIntent},
};
use iroha_test_network::NetworkBuilder;

// Genesis preexecution constructs the full state block even before Tokio starts peers.
// Keep both the owning thread and its runtime workers at the existing network stack size.
const NETWORK_STACK_BYTES: usize = 32 * 1024 * 1024;
// Four isolated validator stores have a combined four-GiB ceiling. This ordinary explicit
// configuration avoids deriving a test allocation from the capacity of a shared host disk.
const LOCAL_STORAGE_BUDGET_BYTES: i64 = 1_073_741_824;

/// Pin each validator's ordinary storage allocation for these bounded local scenarios.
pub fn bounded_storage(builder: NetworkBuilder) -> NetworkBuilder {
    builder.with_config_layer(|writer| {
        writer.write(
            ["nexus", "storage", "local_budget_bytes"],
            LOCAL_STORAGE_BUDGET_BYTES,
        );
    })
}

/// Run genesis preparation and the async scenario on explicit network-sized stacks.
pub fn run<F, Fut>(name: &'static str, body: F) -> Result<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>>,
{
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(NETWORK_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(NETWORK_STACK_BYTES)
                .enable_all()
                .build()
                .wrap_err("build the bounded SoraFS network test runtime")?
                .block_on(body())
        })
        .wrap_err("start the SoraFS network test thread")?;
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Prepare and sign one exact native transaction after independently quoting its fee intent.
pub async fn prepare_transaction(
    client: &Client,
    instructions: impl IntoIterator<Item = impl Into<InstructionBox>>,
    metadata: Metadata,
) -> Result<SignedTransaction> {
    let account = client.account_client();
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        instructions,
        FeePaymentIntent::authority(Vec::new(), None),
        metadata,
    ))?;
    let quote = account
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .await?;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed the selected payer, sponsor revision, or gas bound"
    );
    payload.fee_payment = quote.intent;
    Ok(account.sign_transaction(payload)?)
}

/// Submit one canonical native instruction and require its Applied finality.
pub async fn submit_instruction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
) -> Result<iroha::crypto::HashOf<SignedTransaction>> {
    let transaction = prepare_transaction(client, [instruction], Metadata::default()).await?;
    client
        .account_client()
        .submit_transaction_and_wait(&transaction)
        .await
}
