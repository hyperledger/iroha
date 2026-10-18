//! Live privileged proof revocation preserves exact consent at a certified idle restart.

use super::*;
use iroha_data_model::{ValidationFail, isi::Unregister, sumeragi_finality::VerifiedSumeragiBlock};
use iroha_data_model::{isi::Grant, sumeragi_amx::AmxDebitApprovalV1};
use std::num::NonZeroU64;

async fn assert_disclosure_denied(mut response: reqwest::Response) -> Result<()> {
    ensure!(
        response.status() == reqwest::StatusCode::FORBIDDEN,
        "genuine committed role removal must withhold the full World proof before and after restart; got {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            == Some("private, no-store"),
        "the private bank's denied proof response must remain noncacheable"
    );
    ensure!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            == Some("application/x-norito"),
        "the negotiated denial must be a typed Norito error"
    );
    // Use the existing typed Torii error owner and the exact permission failure.
    // This local acceptance bound is the complete expected error frame itself:
    // no arbitrary error-size allowance can admit a World proof or extra fields.
    let expected = norito::to_bytes(&iroha_torii_shared::ErrorEnvelope::new(
        "query_validation_failed",
        ValidationFail::NotPermitted(
            "Full ledger carriers require CanReadAllLedgerData; use an authorized exact transaction query for selective inclusion".to_owned(),
        ).to_string(),
    ))?;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= u64::try_from(expected.len())?,
            "denial body exceeds its exact error frame"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len()
                .checked_add(chunk.len())
                .is_some_and(|length| length <= expected.len()),
            "denial body exceeds its exact error frame"
        );
        body.extend_from_slice(&chunk);
    }
    ensure!(
        body == expected,
        "denial must contain only the exact full-ledger permission error, with no proof or extra details"
    );
    Ok(())
}

fn verify_preserved_debit(
    root: &Root,
    approval: &AmxDebitApprovalV1,
    expected: &VerifiedSumeragiBlock,
    runtime: &tokio::runtime::Runtime,
) -> Result<()> {
    runtime.block_on(async {
        // The separately authorized bank audit reader authenticates the exact
        // direct permission row after the service's disclosure right is removed.
        let cut = fees::world_cut(root).await?;
        let height = cut
            .attestation
            .body
            .finality_proof
            .block_header
            .height()
            .get();
        ensure!(
            height == expected.height(),
            "revocation recovery must remain at its original tip"
        );
        let mut verifier = root.verifier()?;
        let mut tip = None;
        for next in verifier.authenticated_height().unwrap_or(0) + 1..=height {
            let proof = if next == height {
                cut.attestation.body.finality_proof.clone()
            } else {
                root.client(&genesis_key(root.index))
                    .client()
                    .get_sumeragi_finality_proof_async(NonZeroU64::new(next).unwrap(), root.scope)
                    .await?
            };
            tip = Some(verifier.verify(&proof)?);
        }
        let tip = tip.ok_or_else(|| eyre!("certified revocation cut absent"))?;
        ensure!(tip.block().hash() == expected.block().hash());
        let world = cut.world_snapshot.authenticate(&tip)?;
        ensure!(
            world.schema_hash()
                == iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?
        );
        let permissions = std::collections::BTreeSet::from([approval.permission()?]);
        world.verify_table_value(
            "world.account_permissions",
            &account(&relay(root.index)),
            &permissions,
        )?;
        Ok(())
    })
}

#[test]
#[ignore = "12 validators across 3 roots; set IROHA_TEST_NETWORK_PARALLELISM=3 and use isolated permits with --test-threads=1"]
fn native_bank_read_role_revocation_preserves_debit_after_restart() -> Result<()> {
    let exchange = Exchange::start()?;
    let (_, approvals) = exchange.intent(300, 0xA3)?;
    let mut approved = Vec::new();
    for bank in 0..2 {
        let block = submit(
            &exchange.roots[bank + 1],
            &payer(bank),
            vec![
                Grant::account_permission(approvals[bank].permission()?, account(&relay(bank + 1)))
                    .into(),
            ],
            &exchange.runtime,
        )?;
        exchange
            .runtime
            .block_on(proofs::assert_privileged_bank_approval(
                &exchange.roots[bank + 1],
                &approvals[bank],
                &block,
            ))?;
        approved.push(block);
    }
    // No Begin is submitted: this is deliberate authorization lifecycle work,
    // independent of monetary timeout or relay scheduling.
    let revoked = submit(
        &exchange.roots[1],
        &genesis_key(1),
        vec![Unregister::role(service_read_role()).into()],
        &exchange.runtime,
    )?;
    for restarted in [false, true] {
        if restarted {
            exchange.runtime.block_on(exchange.roots[1].restart_all())?;
        }
        let response = exchange.runtime.block_on(proofs::approval_response(
            &exchange.roots[1],
            &approvals[0],
            revoked.height(),
        ))?;
        exchange
            .runtime
            .block_on(assert_disclosure_denied(response))?;
        verify_preserved_debit(
            &exchange.roots[1],
            &approvals[0],
            &revoked,
            &exchange.runtime,
        )?;
        exchange
            .runtime
            .block_on(proofs::assert_privileged_bank_approval(
                &exchange.roots[2],
                &approvals[1],
                &approved[1],
            ))?;
    }
    let heights = exchange.quiescent_heights()?;
    ensure!(heights[1] == revoked.height() && heights[2] == approved[1].height());
    exchange.audit_fees(heights)?;
    exchange.assert_no_background_blocks(heights)
}
