//! Paid autonomous independent-bank acceptance using the shared real-root harness.
use eyre::{Result, ensure, eyre};
use iroha_data_model::sumeragi_amx::AmxOutcomeV1;
#[path = "support/native_amx_harness.rs"]
mod harness;
#[path = "native_amx_network/read_roles.rs"]
mod read_roles;
use harness::*;
#[test]
#[ignore = "12 validators across 3 roots; set IROHA_TEST_NETWORK_PARALLELISM=3 and use isolated permits with --test-threads=1"]
fn autonomous_two_bank_paid_pvp_survives_all_root_restart_without_successor_traffic() -> Result<()>
{
    let exchange = Exchange::start()?;
    let (transaction, approvals) = exchange.begin(300, 0xA1, false)?;
    let first = exchange.observe(&transaction, &approvals, AmxOutcomeV1::Commit, [true; 2])?;
    let heights = exchange.quiescent_fee_heights()?;
    // A deliberately stale locator exercises the actual authenticated progress
    // path without submitting any successor transaction or changing the final cut.
    // Every root must authenticate its complete paid history before returning it.
    exchange.runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
        for (root, height) in exchange.roots.iter().zip(heights) {
            ensure!(height > 2, "the paid exchange must follow bootstrap");
            let cut = fees::audit(root, height - 1, deadline).await?;
            ensure!(
                cut == fees::FeeCut::Advanced { observed: height },
                "a stale fee locator must return the exact independently authenticated cut"
            );
        }
        Ok::<(), eyre::Report>(())
    })?;
    for root in &exchange.roots {
        exchange.runtime.block_on(root.restart_all())?;
    }
    let recovered = exchange.observe(&transaction, &approvals, AmxOutcomeV1::Commit, [true; 2])?;
    ensure!(
        first.deliveries == recovered.deliveries,
        "restart must reverify the exact original successful settlement carriers"
    );
    exchange.audit_fees(heights)?;
    exchange.assert_no_background_blocks(heights)
}

#[test]
#[ignore = "12 validators across 3 roots; set IROHA_TEST_NETWORK_PARALLELISM=3 and use isolated permits with --test-threads=1"]
fn autonomous_final_silent_bank_aborts_after_relay_restart_and_releases_original_escrow()
-> Result<()> {
    let exchange = Exchange::start()?;
    run_silent_bank_lifecycle(&exchange)
}

// Genesis validation runs on this test's default stack. Keep post-start proof and
// future temporaries out of its call stack while constructing the three roots.
#[inline(never)]
fn run_silent_bank_lifecycle(exchange: &Exchange) -> Result<()> {
    let (transaction, approvals) = exchange.begin(120, 0xA2, true)?;
    exchange.wait_for_first_escrow(&transaction, &approvals[0])?;
    exchange.global_progress(&transaction, false)?;
    ensure!(
        now_ms()? < transaction.expires_at_ms,
        "setup exhausted signed expiry before restart"
    );
    let client = exchange.roots[0].client(&relay(0));
    let before = exchange
        .runtime
        .block_on(status_poll::read_once(
            client.client().torii_request_timeout(),
            || async { client.client().status().get().await.map_err(Into::into) },
        ))?
        .blocks;
    ensure!(
        before < transaction.deadline,
        "height timeout cannot decide this final idle payment"
    );
    // The only Global relay is stopped and resumed from its durable State/archive/workflow
    // owners. No test thread submits Expire, Prepared, Settle, Log or an empty block.
    exchange.runtime.block_on(exchange.roots[0].restart_all())?;
    // Bank A independently verifies the Global Abort and its actual refund while
    // all four bank B validators remain stopped behind a configured delivery route.
    // Its stalled transport must not block the Global expiry or bank A's refund.
    // Restarting B supplies no ledger work; the same service delivers the original decision.
    let abort = exchange.observe(&transaction, &approvals, AmxOutcomeV1::Abort, [true, false])?;
    let expiry = exchange.global_progress(&transaction, true)?;
    let certificate = expiry
        .block()
        .commit_certificate()
        .ok_or_else(|| eyre!("actual Expire carrier has no certificate"))?;
    let original_abort = abort.decisions[0].as_ref().unwrap();
    ensure!(
        original_abort.consensus_header == certificate.consensus_header()
            && original_abort.result_preimage == certificate.result_preimage(),
        "the original certified Abort must be produced by the exact successful autonomous Expire carrier"
    );
    exchange.resume_second_bank()?;
    exchange.observe(&transaction, &approvals, AmxOutcomeV1::Abort, [true; 2])?;
    let after = exchange.quiescent_fee_heights()?;
    ensure!(
        after[0] < transaction.deadline,
        "certified time closure must decide before height expiry"
    );
    exchange.assert_no_background_blocks(after)
}
