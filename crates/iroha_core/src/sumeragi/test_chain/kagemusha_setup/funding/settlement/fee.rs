//! Genuine Send fee execution without Receive, exact historical inputs, and certified replay.
//!
//! This uses the production installed verifier and StateExecutor with a test-signed committee.
//! It is not a four-peer network, native fee-custody acknowledgement, or physical qualification.
//! TODO: Execute with a fresh dedicated native fee producer and its pinned genuine originals.

use super::*;
use iroha_data_model::{
    ValidationFail, isi::error::InstructionExecutionError,
    transaction::error::TransactionRejectionReason,
};
use std::collections::BTreeSet;

const FEE_SCHEMA: &str = "iroha.kagemusha.native-fee-result.v1";
const FEE_NAMES: [&str; 3] = ["request.norito", "payment.norito", "fee-claim.norito"];

fn require_fee_inventory(value: &norito::json::Value) {
    assert_eq!(value["schema"].as_str(), Some(FEE_SCHEMA));
    let rows = value["originals"].as_array().unwrap();
    assert_eq!(rows.len(), FEE_NAMES.len());
    let names = rows
        .iter()
        .map(|row| {
            assert!(row["bytes"].as_u64().is_some_and(|bytes| bytes > 0));
            let text = row["sha256"].as_str().unwrap();
            let digest: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
            assert_ne!(digest, [0; 32]);
            assert_eq!(hex::encode(digest), text);
            row["name"].as_str().unwrap()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, FEE_NAMES.into_iter().collect::<BTreeSet<_>>());
}

fn missing_history_reason() -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::InvariantViolation(
            "KAGEMUSHA ledger: ledger record unavailable".into(),
        ),
    ))
}

fn payout(
    setup: &ExecutedKagemushaSetup,
    scheme: [u8; 32],
    credit: [u8; 32],
) -> Option<KagemushaWalletPayoutRecordV1> {
    let view = setup.chain.state().view();
    view.world()
        .kagemusha_wallet_ledger()
        .get(&KagemushaWalletPayoutKeyV1::Fee(credit).ledger_key(scheme))
        .map(|bytes| canonical(bytes))
}

fn retain_execution(
    setup: &ExecutedKagemushaSetup,
    output: &Path,
    originals: &[(&str, &[u8])],
    fee: KagemushaWalletPayoutRecordV1,
) {
    // Publication is exclusive and starts only after every execution/replay assertion passed.
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory.create(output).unwrap();
    let mut records = originals
        .iter()
        .map(|(name, bytes)| publish(output, name, bytes))
        .collect::<Vec<_>>();
    records.push(publish(
        output,
        "fee-payout.norito",
        &norito::encode_canonical(&fee).unwrap(),
    ));
    let mut verifier = native(setup);
    let mut terminal = None;
    for height in 1..=setup.chain.height() {
        let proof =
            crate::sumeragi::finality::build_proof(&setup.chain.state().view(), height).unwrap();
        let verified = verifier.verify(&proof).unwrap();
        assert_eq!(verified.result(), setup.chain.committed(height).result());
        records.push(publish(
            output,
            &format!("native-proof-{height}.norito"),
            &norito::encode_canonical(&proof).unwrap(),
        ));
        terminal = Some(verified);
    }
    let terminal = terminal.unwrap();
    let tip = setup.chain.committed(setup.chain.height());
    let state = setup.chain.state();
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    // These refusals exercise the same private certified-cut owner without publishing anything.
    let called = std::cell::Cell::new(false);
    let mut changed = fee;
    changed.amount += 1;
    let stale_tip = setup.chain.committed(setup.chain.height() - 1);
    let empty_budget = iroha_allocation::AllocationBudget::new(0);
    for (selected_tip, expected, pool) in [
        (&tip, &changed, &budget),
        (&stale_tip, &fee, &budget),
        (&tip, &fee, &empty_budget),
    ] {
        assert!(
            state
                .with_native_kagemusha_fee_snapshot_for_testing(
                    selected_tip,
                    pin("KAGEMUSHA_WALLET_SCHEME_ID"),
                    expected,
                    pool,
                    |_| {
                        called.set(true);
                        Ok(())
                    },
                )
                .is_err()
        );
        assert!(!called.get());
    }
    let snapshot_record = state
        .with_native_kagemusha_fee_snapshot_for_testing(
            &tip,
            pin("KAGEMUSHA_WALLET_SCHEME_ID"),
            &fee,
            &budget,
            |snapshot| {
                // Retain an explicit finite charge across the authenticated copy and output.
                let _authenticated_copy = budget
                    .try_reserve_bytes(
                        iroha_data_model::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
                    )
                    .map_err(|error| error.to_string())?;
                let world = snapshot
                    .authenticate(&terminal)
                    .map_err(|error| error.to_string())?;
                if world.schema_hash() != crate::state::State::native_world_schema_hash_v1()? {
                    return Err("fee snapshot registry differs from executed native source".into());
                }
                world
                    .verify_table_value(
                        "world.kagemusha_wallet_ledger",
                        &fee.key.ledger_key(pin("KAGEMUSHA_WALLET_SCHEME_ID")),
                        &norito::to_bytes(&fee).map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                let length =
                    norito::canonical_frame_len(snapshot).map_err(|error| error.to_string())?;
                if length > iroha_data_model::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1 {
                    return Err("fee snapshot exceeds canonical frame bound".into());
                }
                let _output_charge = budget
                    .try_reserve_bytes(length)
                    .map_err(|error| error.to_string())?;
                let bytes =
                    norito::encode_canonical(snapshot).map_err(|error| error.to_string())?;
                assert_eq!(bytes.len(), length);
                Ok(publish(output, "world-snapshot.norito", &bytes))
            },
        )
        .unwrap();
    records.push(snapshot_record);
    let evidence_records = records
        .iter()
        .filter(|row| {
            let name = row["name"].as_str().unwrap();
            name == "fee-payout.norito"
                || name == "world-snapshot.norito"
                || name.starts_with("native-proof-")
        })
        .cloned()
        .collect::<Vec<_>>();
    let evidence = norito::json!({
        "schema":"iroha.kagemusha.fee-payout-evidence.v1", "origin":"core",
        "producer_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_FEE_RESULT_SHA256"))),
        "target_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"))),
        "receipt_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"))),
        "scheme_id":(hex::encode(pin("KAGEMUSHA_WALLET_SCHEME_ID"))),
        "manifest_digest":(hex::encode(pin("KAGEMUSHA_WALLET_MANIFEST_DIGEST"))),
        "payout_height":9, "world_height":(terminal.height()), "last_certified_height":(terminal.height()),
        "world_block_hash":(hex::encode(terminal.block().hash().as_ref())),
        "world_context_id":(hex::encode(terminal.context_id().as_ref())),
        "world_root":(hex::encode(terminal.execution().world_state_root.as_ref())),
        "world_schema_hash":(hex::encode(crate::state::State::native_world_schema_hash_v1().unwrap().as_ref())),
        "scope":"Actual ordinary StateExecutor fee payout and complete original certified World cut with a test-signed four-seat committee. Component evidence only; no running four-validator network or physical hardware claim.",
        "originals":evidence_records,
    });
    publish(
        output,
        "fee-payout-evidence.json",
        &norito::json::to_vec(&evidence).unwrap(),
    );
    let result = norito::json!({
        "schema":"iroha.kagemusha.executed-fee-settlement.v1",
        "producer_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_FEE_RESULT_SHA256"))),
        "target_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"))),
        "receipt_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"))),
        "credential_retained_height":6, "missing_request_refusal_height":7,
        "request_retained_height":8, "payout_height":9, "fresh_transaction_retry_heights":[10,11],
        "last_certified_height":(setup.chain.height()),
        "paid_atomic_units":"3", "receiver_payment_atomic_units":"97",
        "balances_atomic_units":["900","0","3","97"],
        "fee_transaction_hash":(hex::encode(fee.transaction)),
        "genuine_installed_proof_execution":true, "receive_required":false,
        "certified_fresh_state_replay":true, "exact_transaction_resubmission":false,
        "scope":"Genuine Send proof fee payout through ordinary Core execution, exact claim bytes in fresh signed transactions, and fresh StateExecutor replay of the exact certified history. Missing Request history is a typed execution refusal, not a proof-negative result. No Receive is executed. Four live validators, native fee-custody acknowledgement, enabled offline controls, nonzero online charges, disk/power-loss and physical-device qualification remain separate.",
        "originals":records
    });
    publish(
        output,
        "settlement.json",
        &norito::json::to_vec(&result).unwrap(),
    );
    File::open(output).unwrap().sync_all().unwrap();
    File::open(output.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
#[ignore = "requires dedicated genuine Send97/fee3 originals under the same loaded A and installed source; executes real Core fee payout without Receive"]
fn execute_actual_send_fee_without_receive_and_with_permanent_replay() {
    let mut setup = start();
    let input = inputs(&setup);
    fund(&mut setup, &input);
    require_funded_receipt(&setup, &input);
    require_conservation(&setup, [900, 0, 0, 100]);
    let selected_result = selected("KAGEMUSHA_NATIVE_FEE_RESULT");
    let producer = read(
        &selected_result,
        16 << 10,
        pin("KAGEMUSHA_NATIVE_FEE_RESULT_SHA256"),
    );
    let result: norito::json::Value = norito::json::from_slice(&producer).unwrap();
    require_fee_inventory(&result);
    for (name, expected) in [
        ("target_sha256", input.target_sha256),
        (
            "receipt_sha256",
            pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
        ),
        ("scheme_id", input.scheme.scheme_id()),
        ("manifest_digest", input.manifest),
    ] {
        assert_eq!(result[name].as_str(), Some(hex::encode(expected).as_str()));
    }
    // Reuse the existing bounded/pinned original reader. Extra producer observations are DATA;
    // only the admitted catalog, signatures and actual execution grant proof/payout authority.
    let inventory = norito::json!({"files":(result["originals"].clone())});
    let root = selected_result.parent().unwrap();
    let request_bytes = original(
        root,
        &inventory,
        FEE_NAMES[0],
        KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1,
    );
    let payment_bytes = original(
        root,
        &inventory,
        FEE_NAMES[1],
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let claim_bytes = original(
        root,
        &inventory,
        FEE_NAMES[2],
        KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1,
    );
    let request: KagemushaWalletRequestV1 = canonical(&request_bytes);
    let claim =
        KagemushaWalletFeeClaimV1::decode_canonical(&claim_bytes, &input.scheme.scheme_id())
            .unwrap();
    assert_eq!(
        norito::encode_canonical(&claim.payment).unwrap(),
        payment_bytes
    );
    let activation =
        KagemushaWalletActivationV1::decode_canonical(&input.activation, &input.scheme.scheme_id())
            .unwrap();
    assert_eq!(
        claim.payment.digests().unwrap().payer_credential,
        activation.credential.credential_digest()
    );
    assert_eq!(
        request.body.payer_wallet_id,
        activation.credential.body.wallet_id
    );
    assert_eq!(
        request.body.payer_account_digest,
        kagemusha_wallet_account_digest_v1(&setup.account).unwrap()
    );
    assert_eq!(
        request.body.receiver_account_digest,
        kagemusha_wallet_account_digest_v1(&setup.recipients[0]).unwrap()
    );
    assert_eq!(claim.beneficiary, setup.recipients[1]);
    assert_eq!((request.body.amount, request.body.fee), (97, 3));
    assert_eq!(
        (
            claim.payment.send.statement.next_load,
            claim.payment.send.statement.enabled_controls
        ),
        (1, 0)
    );
    let verified = claim
        .verify(
            &input.scheme,
            &request,
            &activation.credential,
            &activation.certificates,
        )
        .unwrap();
    assert_eq!(verified.fee, 3);
    let credit = verified.credit_id;
    assert_eq!(payout(&setup, input.scheme.scheme_id(), credit), None);

    // Activate records a wallet, not the historical credential required by fee_inputs.
    let retain_payer = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::RetainCredential {
            credential: activation.credential.to_canonical_bytes().unwrap(),
            certificates: norito::encode_canonical(&activation.certificates).unwrap(),
        },
    );
    let tx = setup.chain.sign(&key(41), [retain_payer.into()], 5_999);
    assert_eq!(setup.chain.commit_at(6_000, vec![tx]), [true]);
    require_conservation(&setup, [900, 0, 0, 100]);
    let before_missing = ledger_rows(&setup);
    let instruction = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::ClaimFee(claim_bytes.clone()),
    );
    let tx = setup
        .chain
        .sign(&key(42), [instruction.clone().into()], 6_999);
    assert_eq!(setup.chain.commit_at(7_000, vec![tx]), [false]);
    assert_eq!(
        setup.chain.committed(7).block().output_error(0),
        Some(&missing_history_reason())
    );
    assert_eq!(ledger_rows(&setup), before_missing);
    assert_eq!(payout(&setup, input.scheme.scheme_id(), credit), None);
    require_conservation(&setup, [900, 0, 0, 100]);

    let retain_request = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::RetainRequest(request_bytes.clone()),
    );
    let tx = setup.chain.sign(&key(42), [retain_request.into()], 7_999);
    assert_eq!(setup.chain.commit_at(8_000, vec![tx]), [true]);
    require_conservation(&setup, [900, 0, 0, 100]);
    // B may relay before Receive, but cannot redirect the fee away from its signed beneficiary C.
    let tx = setup
        .chain
        .sign(&key(42), [instruction.clone().into()], 8_999);
    let paid_transaction = *tx.hash().as_ref();
    assert_eq!(setup.chain.commit_at(9_000, vec![tx]), [true]);
    require_conservation(&setup, [900, 0, 3, 97]);
    let paid = payout(&setup, input.scheme.scheme_id(), credit).unwrap();
    assert_eq!(
        paid,
        KagemushaWalletPayoutRecordV1 {
            key: KagemushaWalletPayoutKeyV1::Fee(credit),
            source: verified.payment,
            amount: 3,
            transaction: paid_transaction,
        }
    );
    let paid_rows = ledger_rows(&setup);
    let tx = setup
        .chain
        .sign(&key(41), [instruction.clone().into()], 9_999);
    assert_ne!(*tx.hash().as_ref(), paid_transaction);
    assert_eq!(setup.chain.commit_at(10_000, vec![tx]), [true]);
    assert_eq!(ledger_rows(&setup), paid_rows);
    require_conservation(&setup, [900, 0, 3, 97]);
    setup = replay_into_fresh_state(setup);
    require_funded_receipt(&setup, &input);
    assert_eq!(payout(&setup, input.scheme.scheme_id(), credit), Some(paid));
    let tx = setup
        .chain
        .sign(&key(43), [instruction.clone().into()], 10_999);
    assert_ne!(*tx.hash().as_ref(), paid_transaction);
    assert_eq!(setup.chain.commit_at(11_000, vec![tx]), [true]);
    assert_eq!(ledger_rows(&setup), paid_rows);
    require_conservation(&setup, [900, 0, 3, 97]);
    setup = replay_into_fresh_state(setup);
    assert_eq!(ledger_rows(&setup), paid_rows);
    require_conservation(&setup, [900, 0, 3, 97]);
    retain_execution(
        &setup,
        &selected("KAGEMUSHA_EXECUTED_FEE_OUTPUT"),
        &[
            ("producer.json", &producer),
            (FEE_NAMES[0], &request_bytes),
            (FEE_NAMES[1], &payment_bytes),
            (FEE_NAMES[2], &claim_bytes),
            (
                "fee-instruction.norito",
                &norito::encode_canonical(&instruction).unwrap(),
            ),
        ],
        paid,
    );
}

#[test]
fn fee_inventory_requires_exact_original_roles_and_canonical_pins() {
    let rows =
        FEE_NAMES.map(|name| norito::json!({"name":name,"bytes":1,"sha256":(hex::encode([7;32]))}));
    let valid = norito::json!({"schema":FEE_SCHEMA,"originals":rows});
    require_fee_inventory(&valid);
    for mode in 0..5 {
        let mut changed = valid.clone();
        let rows = changed
            .as_object_mut()
            .unwrap()
            .get_mut("originals")
            .unwrap()
            .as_array_mut()
            .unwrap();
        match mode {
            0 => {
                rows.pop();
            }
            1 => {
                rows.push(rows[0].clone());
            }
            2 => {
                rows[1] = rows[0].clone();
            }
            3 => {
                rows[0]
                    .as_object_mut()
                    .unwrap()
                    .insert("name".into(), "../foreign.norito".into());
            }
            _ => {
                rows[0]
                    .as_object_mut()
                    .unwrap()
                    .insert("sha256".into(), "07".into());
            }
        }
        assert!(std::panic::catch_unwind(|| require_fee_inventory(&changed)).is_err());
    }
}
