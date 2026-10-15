//! Genuine online Load-charge and quoted Unload execution through ordinary StateExecutor.
//!
//! Each scenario starts a fresh component chain from the same genuine dedicated target.
//! Real installed Bootstrap/Unload proofs are mandatory; no World rows or verifier results
//! are injected. Committee signing is a test fixture, not four live validators.
//! TODO: Compile and execute both ignored tests with the paired current-source native producer.

use super::*;

mod continuation;
use iroha_data_model::{
    ValidationFail,
    isi::{
        error::{InstructionExecutionError, MathError},
        kagemusha_wallet::{KagemushaWalletLoadChargeV1, KagemushaWalletLoadReceiptV1},
    },
    transaction::error::TransactionRejectionReason,
};
use std::collections::BTreeSet;

const NAMES: [&str; 7] = [
    "regulatory-certificate.norito",
    "load-quote.norito",
    "stale-load-quote.norito",
    "exhausting-load-quote.norito",
    "unload-quote.norito",
    "stale-unload-quote.norito",
    "unload-claim.norito",
];

fn inventory(value: &norito::json::Value) {
    assert_eq!(
        value["schema"].as_str(),
        Some("iroha.kagemusha.native-online-charge-result.v1")
    );
    assert_eq!(value["variant"].as_str(), Some("online-charges"));
    let rows = value["originals"].as_array().unwrap();
    assert_eq!(rows.len(), NAMES.len());
    let names = rows
        .iter()
        .map(|row| {
            assert!(row["bytes"].as_u64().is_some_and(|n| n > 0));
            let text = row["sha256"].as_str().unwrap();
            let digest: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
            assert_ne!(digest, [0; 32]);
            assert_eq!(hex::encode(digest), text);
            row["name"].as_str().unwrap()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, NAMES.into_iter().collect::<BTreeSet<_>>());
}

struct Charges {
    producer: Vec<u8>,
    originals: Vec<(&'static str, Vec<u8>)>,
    certificate: KagemushaWalletSignerCertificateV1,
    load: KagemushaWalletChargeQuoteV1,
    stale_load: KagemushaWalletChargeQuoteV1,
    exhausting_load: KagemushaWalletChargeQuoteV1,
    stale_unload: KagemushaWalletChargeQuoteV1,
    claim: KagemushaWalletUnloadClaimV1,
    claim_bytes: Vec<u8>,
}

fn inputs_for_charges(setup: &ExecutedKagemushaSetup, input: &Inputs) -> Charges {
    let path = selected("KAGEMUSHA_NATIVE_CHARGE_RESULT");
    let producer = read(
        &path,
        16 << 10,
        pin("KAGEMUSHA_NATIVE_CHARGE_RESULT_SHA256"),
    );
    let value: norito::json::Value = norito::json::from_slice(&producer).unwrap();
    inventory(&value);
    for (field, expected) in [
        ("target_sha256", input.target_sha256),
        (
            "receipt_sha256",
            pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
        ),
        ("scheme_id", input.scheme.scheme_id()),
        ("manifest_digest", input.manifest),
    ] {
        assert_eq!(value[field].as_str(), Some(hex::encode(expected).as_str()));
    }
    let target: norito::json::Value = norito::json::from_slice(&read(
        &selected("KAGEMUSHA_NATIVE_LOAD_TARGET"),
        16 << 10,
        input.target_sha256,
    ))
    .unwrap();
    assert_eq!(target["variant"].as_str(), Some("online-charges"));
    let rows = norito::json!({"files":(value["originals"].clone())});
    let originals = NAMES
        .into_iter()
        .map(|name| {
            let maximum = if name == "unload-claim.norito" {
                KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1
            } else if name == "regulatory-certificate.norito" {
                KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1
            } else {
                KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1
            };
            (name, original(path.parent().unwrap(), &rows, name, maximum))
        })
        .collect::<Vec<_>>();
    let certificate: KagemushaWalletSignerCertificateV1 = canonical(&originals[0].1);
    certificate.verify(&input.scheme).unwrap();
    assert_eq!(
        certificate.body.role,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy
    );
    let quotes = originals[1..6]
        .iter()
        .map(|(_, bytes)| {
            KagemushaWalletChargeQuoteV1::decode_canonical(bytes, &input.scheme.scheme_id())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let activation =
        KagemushaWalletActivationV1::decode_canonical(&input.activation, &input.scheme.scheme_id())
            .unwrap();
    assert_eq!(
        value["payer_wallet_id"].as_str(),
        Some(hex::encode(activation.credential.body.wallet_id).as_str())
    );
    for quote in &quotes {
        quote.verify(&input.scheme, &certificate).unwrap();
        assert_eq!(quote.body.wallet_id, activation.credential.body.wallet_id);
        assert_eq!(quote.body.asset_digest, setup.asset.asset_digest());
        assert_eq!(
            quote.body.beneficiary_account_digest,
            kagemusha_wallet_account_digest_v1(&setup.recipients[1]).unwrap()
        );
    }
    for (quote, (kind, ordinal, amount, charge)) in quotes.iter().zip([
        (KagemushaWalletChargeKindV1::Load, 1, 100, 3),
        (KagemushaWalletChargeKindV1::Load, 0, 100, 3),
        (KagemushaWalletChargeKindV1::Load, 1, 900, 3),
        (KagemushaWalletChargeKindV1::Unload, 0, 100, 5),
        (KagemushaWalletChargeKindV1::Unload, 1, 100, 5),
    ]) {
        quote
            .require_terms(
                kind,
                &activation.credential.body.wallet_id,
                ordinal,
                amount,
                charge,
            )
            .unwrap();
    }
    let claim_bytes = originals[6].1.clone();
    let claim =
        KagemushaWalletUnloadClaimV1::decode_canonical(&claim_bytes, &input.scheme.scheme_id())
            .unwrap();
    assert_eq!(claim.credential, activation.credential);
    assert_eq!(claim.account, setup.account);
    assert_eq!(claim.charge.quote(), Some(&quotes[3]));
    let paid = claim.verify(&input.scheme).unwrap();
    assert_eq!(
        (paid.amount, paid.account_payout, paid.online_charge),
        (100, 95, 5)
    );
    assert_eq!(
        (
            claim.package.statement.next_load,
            claim.package.statement.enabled_controls
        ),
        (1, 0)
    );
    Charges {
        producer,
        certificate,
        load: quotes[0],
        stale_load: quotes[1],
        exhausting_load: quotes[2],
        stale_unload: quotes[4],
        claim,
        claim_bytes,
        originals,
    }
}

fn rejection(error: InstructionExecutionError) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(error))
}

fn ledger_error(message: &str) -> TransactionRejectionReason {
    rejection(InstructionExecutionError::InvariantViolation(
        format!("KAGEMUSHA ledger: {message}").into(),
    ))
}

fn model_error(field: &'static str) -> TransactionRejectionReason {
    ledger_error(&KagemushaWalletValidationErrorV1::InvalidField { field }.to_string())
}

fn execute(
    setup: &mut ExecutedKagemushaSetup,
    seed: u8,
    instruction: KagemushaWalletLedgerV1,
    expected: Option<TransactionRejectionReason>,
) -> [u8; 32] {
    let height = setup.chain.height() + 1;
    let tx = setup
        .chain
        .sign(&key(seed), [instruction.into()], height * 1_000 - 1);
    let hash = *tx.hash().as_ref();
    assert_eq!(
        setup.chain.commit_at(height * 1_000, vec![tx]),
        [expected.is_none()]
    );
    let committed = setup.chain.committed(height);
    assert_eq!(committed.block().external_transactions().count(), 1);
    assert_eq!(committed.block().output_error(0), expected.as_ref());
    hash
}

fn load_command(
    input: &Inputs,
    quote: &KagemushaWalletChargeQuoteV1,
    beneficiary: AccountId,
    request: u8,
) -> KagemushaWalletLedgerV1 {
    KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::IssueLoad {
            wallet: quote.body.wallet_id,
            asset: quote.body.asset_digest,
            ordinal: 1,
            request_id: [request; 32],
            amount: quote.body.net_amount,
            charge: Some(KagemushaWalletLoadChargeV1 {
                quote: quote.to_canonical_bytes().unwrap(),
                beneficiary,
            }),
        },
    )
}

fn charged_receipt(
    setup: &ExecutedKagemushaSetup,
    input: &Inputs,
    quote: &KagemushaWalletChargeQuoteV1,
    height: u64,
) -> KagemushaWalletLoadReceiptV1 {
    let mut cursor = crate::sumeragi::finality::NativeFinalityCursorV1::new();
    let budget = iroha_allocation::AllocationBudget::new(2 << 30);
    let view = setup.chain.state().view();
    let at = cursor
        .advance_to_height(
            &view,
            NonZeroU64::new(height).unwrap(),
            &budget,
            Instant::now() + Duration::from_secs(60),
            NonZeroU16::new(64).unwrap(),
        )
        .unwrap()
        .unwrap();
    let source =
        CommittedLoadReceipts::new(&view, 2_000_000, norito::canonical_decode_limits(2_000_000))
            .unwrap();
    let evidence = source
        .event_evidence_for(
            &at,
            &setup.account,
            &input.scheme.scheme_id(),
            &quote.body.wallet_id,
            &[249; 32],
        )
        .unwrap();
    let receipt = *evidence.verified().receipt();
    assert_eq!(
        (
            receipt.ordinal,
            receipt.amount,
            receipt.online_charge,
            receipt.block_height
        ),
        (1, 100, 3, height)
    );
    receipt.require_charge_quote(Some(quote)).unwrap();
    assert_eq!(receipt.ledger_debit().unwrap(), 103);
    receipt
}

fn retain(
    setup: &ExecutedKagemushaSetup,
    charges: &Charges,
    scenario: &str,
    amounts: [u128; 4],
    row: &[u8],
) {
    let output = selected(if scenario == "load" {
        "KAGEMUSHA_EXECUTED_CHARGED_LOAD_OUTPUT"
    } else {
        "KAGEMUSHA_EXECUTED_CHARGED_UNLOAD_OUTPUT"
    });
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory.create(&output).unwrap();
    let mut records = charges
        .originals
        .iter()
        .map(|(name, bytes)| publish(&output, name, bytes))
        .collect::<Vec<_>>();
    records.push(publish(&output, "producer.json", &charges.producer));
    records.push(publish(&output, "executed-row.norito", row));
    let mut verifier = native(setup);
    for height in 1..=setup.chain.height() {
        let proof =
            crate::sumeragi::finality::build_proof(&setup.chain.state().view(), height).unwrap();
        let block = verifier.verify(&proof).unwrap();
        assert_eq!(block.result(), setup.chain.committed(height).result());
        records.push(publish(
            &output,
            &format!("native-proof-{height}.norito"),
            &norito::encode_canonical(&proof).unwrap(),
        ));
    }
    publish(&output,"result.json",&norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.executed-online-charge.v1","scenario":scenario,
        "producer_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_CHARGE_RESULT_SHA256"))),
        "target_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"))),
        "last_certified_height":(setup.chain.height()),"balances_atomic_units":(amounts.map(|x|x.to_string()).to_vec()),
        "certified_fresh_state_replay":true,"exact_transport_resubmission":false,
        "scope":"Actual ordinary signed Core execution with production installed proof verification and test-signed committee. Exact certified transaction history replay and fresh signed retry are covered. No four live peers, transport retry, native charged-Load absorption, native payout acknowledgement, physical hardware or release qualification.",
        "originals":records,
    })).unwrap());
    File::open(&output).unwrap().sync_all().unwrap();
}

#[test]
fn online_charge_inventory_is_closed_and_errors_remain_typed() {
    let rows = NAMES
        .into_iter()
        .map(|name| norito::json!({"name":name,"bytes":1,"sha256":(hex::encode([1;32]))}))
        .collect::<Vec<_>>();
    let value = norito::json!({"schema":"iroha.kagemusha.native-online-charge-result.v1","variant":"online-charges","originals":rows});
    inventory(&value);
    for mode in 0..3 {
        let mut changed = value.clone();
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
            1 => rows[1] = rows[0].clone(),
            _ => {
                rows[0]
                    .as_object_mut()
                    .unwrap()
                    .insert("name".into(), "../foreign".into());
            }
        }
        assert!(std::panic::catch_unwind(|| inventory(&changed)).is_err());
    }
    assert_eq!(
        model_error("charge_quote.ordinal"),
        ledger_error("invalid KAGEMUSHA wallet V1 field `charge_quote.ordinal`")
    );
}

#[test]
#[ignore = "requires dedicated genuine online-charge target/result and installed catalog; executes charged Load with ordinary StateExecutor"]
fn actual_charged_load_is_atomic_and_retains_exact_receipt_through_replay() {
    let mut setup = start();
    let input = inputs(&setup);
    fund(&mut setup, &input);
    require_funded_receipt(&setup, &input);
    let charges = inputs_for_charges(&setup, &input);
    require_conservation(&setup, [900, 0, 0, 100]);
    let before = ledger_rows(&setup);
    let good = load_command(&input, &charges.load, setup.recipients[1].clone(), 249);
    execute(
        &mut setup,
        41,
        good.clone(),
        Some(ledger_error("ledger record unavailable")),
    );
    assert_eq!(ledger_rows(&setup), before);
    require_conservation(&setup, [900, 0, 0, 100]);
    let retain_certificate = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::RetainCertificate {
            asset: setup.asset.asset_digest(),
            certificate: norito::encode_canonical(&charges.certificate).unwrap(),
        },
    );
    execute(&mut setup, 41, retain_certificate, None);
    let before = ledger_rows(&setup);
    let wrong = load_command(&input, &charges.load, setup.recipients[0].clone(), 245);
    let stale = load_command(
        &input,
        &charges.stale_load,
        setup.recipients[1].clone(),
        246,
    );
    let insolvent = load_command(
        &input,
        &charges.exhausting_load,
        setup.recipients[1].clone(),
        247,
    );
    for (instruction, reason) in [
        (wrong, ledger_error("ledger source binding differs")),
        (stale, model_error("charge_quote.ordinal")),
        (
            insolvent,
            rejection(InstructionExecutionError::Math(
                MathError::NotEnoughQuantity,
            )),
        ),
    ] {
        execute(&mut setup, 41, instruction, Some(reason));
        assert_eq!(
            ledger_rows(&setup),
            before,
            "failed deposit/charge cannot consume ordinal or publish issuance"
        );
        require_conservation(&setup, [900, 0, 0, 100]);
    }
    let hash = execute(&mut setup, 41, good.clone(), None);
    let paid_height = setup.chain.height();
    require_conservation(&setup, [797, 0, 3, 200]);
    let receipt = charged_receipt(&setup, &input, &charges.load, paid_height);
    assert_eq!(receipt.transaction_hash, hash);
    let rows = ledger_rows(&setup);
    execute(
        &mut setup,
        41,
        good.clone(),
        Some(ledger_error("permanent replay key conflicts")),
    );
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [797, 0, 3, 200]);
    setup = replay_into_fresh_state(setup);
    assert_eq!(
        charged_receipt(&setup, &input, &charges.load, paid_height),
        receipt
    );
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [797, 0, 3, 200]);
    execute(
        &mut setup,
        41,
        good,
        Some(ledger_error("permanent replay key conflicts")),
    );
    let stale = load_command(&input, &charges.load, setup.recipients[1].clone(), 250);
    execute(
        &mut setup,
        41,
        stale,
        Some(ledger_error("permanent replay key conflicts")),
    );
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [797, 0, 3, 200]);
    setup = replay_into_fresh_state(setup);
    assert_eq!(
        charged_receipt(&setup, &input, &charges.load, paid_height),
        receipt
    );
    require_conservation(&setup, [797, 0, 3, 200]);
    retain(
        &setup,
        &charges,
        "load",
        [797, 0, 3, 200],
        &norito::encode_canonical(&receipt).unwrap(),
    );
}

#[test]
#[ignore = "requires dedicated genuine quoted Unload100/charge5 native claim and installed catalog; executes ordinary Core payout/replay"]
fn actual_charged_unload_pays_account_and_beneficiary_exactly_once() {
    let mut setup = start();
    let input = inputs(&setup);
    fund(&mut setup, &input);
    require_funded_receipt(&setup, &input);
    let charges = inputs_for_charges(&setup, &input);
    let paid = charges.claim.verify(&input.scheme).unwrap();
    let before = ledger_rows(&setup);
    let mut wrong = charges.claim.clone();
    let KagemushaWalletUnloadChargeV1::Quoted { beneficiary, .. } = &mut wrong.charge else {
        panic!("quoted Unload")
    };
    *beneficiary = setup.recipients[0].clone();
    let mut stale = charges.claim.clone();
    let KagemushaWalletUnloadChargeV1::Quoted { quote, .. } = &mut stale.charge else {
        panic!("quoted Unload")
    };
    *quote = charges.stale_unload;
    for (claim, reason) in [
        (&wrong, model_error("unload_claim.beneficiary")),
        (&stale, model_error("effect.charge_quote")),
    ] {
        execute(
            &mut setup,
            41,
            KagemushaWalletLedgerV1::new(
                input.scheme.scheme_id(),
                Action::Unload(norito::encode_canonical(claim).unwrap()),
            ),
            Some(reason),
        );
        assert_eq!(ledger_rows(&setup), before);
        require_conservation(&setup, [900, 0, 0, 100]);
    }
    let instruction = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::Unload(charges.claim_bytes.clone()),
    );
    let transaction = execute(&mut setup, 42, instruction.clone(), None);
    require_conservation(&setup, [995, 0, 5, 0]);
    let key =
        KagemushaWalletPayoutKeyV1::Unload(paid.nullifier).ledger_key(input.scheme.scheme_id());
    let payout = KagemushaWalletPayoutRecordV1 {
        key: KagemushaWalletPayoutKeyV1::Unload(paid.nullifier),
        source: paid.package,
        amount: 100,
        transaction,
    };
    let rows = ledger_rows(&setup);
    assert_eq!(
        rows.iter().find(|(id, _)| *id == key).unwrap().1,
        norito::encode_canonical(&payout).unwrap()
    );
    let retry = execute(&mut setup, 41, instruction.clone(), None);
    assert_ne!(retry, transaction);
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [995, 0, 5, 0]);
    setup = replay_into_fresh_state(setup);
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [995, 0, 5, 0]);
    execute(&mut setup, 43, instruction, None);
    // Malformed bindings stay refused after the payout exists; they cannot exploit retry.
    for (claim, reason) in [
        (&wrong, model_error("unload_claim.beneficiary")),
        (&stale, model_error("effect.charge_quote")),
    ] {
        execute(
            &mut setup,
            41,
            KagemushaWalletLedgerV1::new(
                input.scheme.scheme_id(),
                Action::Unload(norito::encode_canonical(claim).unwrap()),
            ),
            Some(reason),
        );
        assert_eq!(ledger_rows(&setup), rows);
        require_conservation(&setup, [995, 0, 5, 0]);
    }
    setup = replay_into_fresh_state(setup);
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [995, 0, 5, 0]);
    retain(
        &setup,
        &charges,
        "unload",
        [995, 0, 5, 0],
        &norito::encode_canonical(&payout).unwrap(),
    );
}
