//! Ordinary reserve availability refusal and recovery of the exact genuine Unload claim.
//!
//! The asset owner changes committed policy; no wallet proof or payment signature is
//! regenerated. A certified typed failure must leave the full reserve intact. The parent
//! then settles the unchanged claim, checks exact/fresh retries and restarts all four peers.
//! TODO: Execute this successor with the current source-qualified four-validator campaign.

use super::*;
use iroha_data_model::{asset::AssetTransferAvailability, isi::SetAssetTransferAvailability};

fn outgoing_disabled() -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::OutgoingDisabled(
                format!(
                    "account {} on asset definition {} at availability revision 1",
                    account(95),
                    definition_id()
                )
                .into(),
            ),
        ),
    ))
}

// The genesis asset owner is ALICE, not the reserve account. Use the ordinary
// owner client and fee quote; retaining its signed original precedes dispatch.
fn set_availability(
    network: &Network,
    output: &Path,
    expected_revision: u64,
    outgoing: AssetTransferAvailability,
    name: &str,
) -> Result<norito::json::Value> {
    let client = running_peer(network)?.client();
    let instruction = SetAssetTransferAvailability::new(
        account(95),
        definition_id(),
        expected_revision,
        AssetTransferAvailability::Enabled,
        outgoing,
        None,
    );
    let mut payload = client
        .account_client()
        .prepare_transaction(AccountTransactionDraft::new(
            vec![instruction.into()],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))?;
    let quote = client.quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })?;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "policy fee quote changed payer or gas bound"
    );
    payload.fee_payment = quote.intent;
    let transaction = client.account_client().sign_transaction(payload)?;
    ensure!(
        transaction.authority() == &*iroha_test_samples::ALICE_ID,
        "availability changes require the genesis asset owner"
    );
    let original = canonical_observation(output, name, &transaction, ORIGINAL_MAX)?;
    File::open(output)?.sync_all()?;
    ensure!(
        client.submit_transaction_and_wait(&transaction)? == transaction.hash(),
        "policy submission returned a foreign transaction hash"
    );
    let through = committed_height(network)?;
    let mut verifier = native(network)?;
    let mut found = None;
    for proof in prefix(network, through)? {
        let block = verifier.verify(&proof)?;
        if block
            .block()
            .network_entrypoints()
            .any(|entry| entry.hash().as_ref() == transaction.hash().as_ref())
        {
            ensure!(found.is_none(), "policy transaction appears twice");
            inclusion(&block, network, &transaction)?;
            found = Some(block.height());
        }
    }
    let height = found.ok_or_else(|| eyre!("policy update absent from certified history"))?;
    balances(network, [900, 0, 0, 100])?;
    Ok(norito::json!({
        "height":height,
        "transaction_hash_hex":(hex::encode(transaction.hash().as_ref())),
        "signed_original":original
    }))
}

pub(super) fn before_payout(
    network: &Network,
    output: &Path,
    instruction: &KagemushaWalletLedgerV1,
) -> Result<norito::json::Value> {
    // Sign while the reserve is available, so an ordinary preparation-time policy
    // check cannot replace the required certified refusal. The signed original
    // remains unchanged while the asset owner commits the disabling update.
    let transaction = signed(network, 43, vec![instruction.clone().into()])?;
    let transaction_hash = hex::encode(transaction.hash().as_ref());
    let disabled = set_availability(
        network,
        output,
        0,
        AssetTransferAvailability::Disabled,
        "reserve-outgoing-disable-policy-signed.norito",
    )?;
    let refusal = refused(
        network,
        output,
        43,
        transaction,
        &outgoing_disabled(),
        [900, 0, 0, 100],
        "reserve-outgoing-disabled",
    )?;
    ensure!(
        refusal["qualified"].as_bool() == Some(true),
        "reserve policy refusal requires the exact native-certified execution reason"
    );
    let enabled = set_availability(
        network,
        output,
        1,
        AssetTransferAvailability::Enabled,
        "reserve-outgoing-enable-policy-signed.norito",
    )?;
    let evidence = norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.network-unload-policy-retry.v1",
        "instruction_sha256":(hash(&norito::encode_canonical(instruction)?)),
        "disabled":disabled, "refused":refusal, "enabled":enabled,
        "balances_before_payout":[900, 0, 0, 100],
        "scope":"Ordinary asset-owner availability changes and certified OutgoingDisabled refusal preserve the entire reserve. This record precedes payout; the parent settlement must pay the identical claim and independently retain its successful execution. No wallet proof or payment receipt is re-signed."
    }))?;
    let original = publish(output, "policy-retry.json", &evidence)?;
    File::open(output)?.sync_all()?;
    Ok(norito::json!({
        "certified_policy_refusal":true,
        "refused_transaction_hash_hex":transaction_hash,
        "observation_original":original
    }))
}

#[test]
fn policy_failure_requires_exact_reserve_asset_revision_and_direction() {
    let expected = outgoing_disabled();
    let failed = TransactionResult::new(Err(expected.clone()));
    assert_eq!(claim_failure(&failed, &expected).unwrap(), &expected);
    let encoded = norito::encode_canonical(claim_failure(&failed, &expected).unwrap()).unwrap();
    assert_eq!(
        canonical::<TransactionRejectionReason>(&encoded).unwrap(),
        expected
    );
    for detail in [
        format!(
            "account {} on asset definition {} at availability revision 1",
            account(43),
            definition_id()
        ),
        format!(
            "account {} on asset definition {} at availability revision 2",
            account(95),
            definition_id()
        ),
        format!(
            "account {} on asset definition foreign at availability revision 1",
            account(95)
        ),
    ] {
        let changed = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::OutgoingDisabled(detail.into()),
            ),
        ));
        assert!(claim_failure(&TransactionResult::new(Err(changed)), &expected).is_err());
    }
    for changed in [
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::IncomingDisabled("wrong direction".into()),
            ),
        )),
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvariantViolation("native package proof rejected".into()),
        )),
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
            "fee rejection".into(),
        )),
    ] {
        assert!(claim_failure(&TransactionResult::new(Err(changed)), &expected).is_err());
    }
    assert!(claim_failure(&TransactionResult::new(Ok(Vec::new())), &expected).is_err());
}
