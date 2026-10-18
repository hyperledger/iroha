//! One certified chain returns the later charged Load to the same pending-Unload wallet.
//!
//! The native producer has already consumed its first 100 into an exact Unload claim.
//! Ordinary execution issues the next Load100+charge3, then pays that Unload95+charge5.
//! TODO: Compile and run with current genuine artifacts; this is a component committee fixture.

use super::*;
use iroha_data_model::sumeragi_finality::SumeragiCommitCertificateV1;

fn load_evidence(
    setup: &ExecutedKagemushaSetup,
    input: &Inputs,
    quote: &KagemushaWalletChargeQuoteV1,
    height: u64,
) -> (KagemushaWalletLoadReceiptV1, KagemushaWalletLoadFinalityV1) {
    let mut cursor =
        crate::sumeragi::finality::NativeFinalityCursorV1::new(setup.chain.root_scope());
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
    let original = source
        .event_evidence_for(
            &at,
            &setup.account,
            &input.scheme.scheme_id(),
            &quote.body.wallet_id,
            &[249; 32],
        )
        .unwrap();
    let receipt = *original.verified().receipt();
    assert_eq!(receipt, charged_receipt(setup, input, quote, height));
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1::from_verified(at.block()).unwrap(),
        event_proof: original.path().proof().unwrap(),
    };
    evidence.verify(&native(setup), &receipt).unwrap();
    (receipt, evidence)
}

fn bounded_original(
    output: &Path,
    name: &str,
    bytes: &[u8],
    maximum: usize,
) -> norito::json::Value {
    // Retain the complete carrying original and measurement before a bound failure.
    let row = publish(output, name, bytes);
    publish(output, &format!("{name}.measurement.json"), &norito::json::to_vec(&norito::json!({
        "name":name,"bytes":(bytes.len()),"maximum_bytes":maximum,"within_bound":(bytes.len() <= maximum),
    })).unwrap());
    assert!(!bytes.is_empty() && bytes.len() <= maximum);
    row
}

#[test]
#[ignore = "requires dedicated native quoted Unload and installed catalog; emits actual same-chain later Load event/finality for original custody"]
fn actual_charged_load_then_unload_exports_same_chain_native_absorption() {
    let mut setup = start();
    let input = inputs(&setup);
    fund(&mut setup, &input);
    require_funded_receipt(&setup, &input);
    let charges = inputs_for_charges(&setup, &input);
    require_conservation(&setup, [900, 0, 0, 100]);
    let retain = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::RetainCertificate {
            asset: setup.asset.asset_digest(),
            certificate: norito::encode_canonical(&charges.certificate).unwrap(),
        },
    );
    execute(&mut setup, 41, retain, None);
    let load = load_command(&input, &charges.load, setup.recipients[1].clone(), 249);
    let load_transaction = execute(&mut setup, 41, load.clone(), None);
    let load_height = setup.chain.height();
    require_conservation(&setup, [797, 0, 3, 200]);
    let (receipt, evidence) = load_evidence(&setup, &input, &charges.load, load_height);
    assert_eq!(receipt.transaction_hash, load_transaction);
    let paid = charges.claim.verify(&input.scheme).unwrap();
    let unload = KagemushaWalletLedgerV1::new(
        input.scheme.scheme_id(),
        Action::Unload(charges.claim_bytes.clone()),
    );
    let unload_transaction = execute(&mut setup, 42, unload.clone(), None);
    let unload_height = setup.chain.height();
    assert!(load_height < unload_height);
    require_conservation(&setup, [892, 0, 8, 100]);
    let payout = KagemushaWalletPayoutRecordV1 {
        key: KagemushaWalletPayoutKeyV1::Unload(paid.nullifier),
        source: paid.package,
        amount: 100,
        transaction: unload_transaction,
    };
    let payout_bytes = norito::encode_canonical(&payout).unwrap();
    let row_key = payout.key.ledger_key(input.scheme.scheme_id());
    let rows = ledger_rows(&setup);
    assert_eq!(
        rows.iter().find(|(key, _)| *key == row_key).unwrap().1,
        payout_bytes
    );
    execute(
        &mut setup,
        41,
        load.clone(),
        Some(ledger_error("permanent replay key conflicts")),
    );
    let retry = execute(&mut setup, 41, unload.clone(), None);
    assert_ne!(retry, unload_transaction);
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [892, 0, 8, 100]);
    setup = replay_into_fresh_state(setup);
    assert_eq!(
        load_evidence(&setup, &input, &charges.load, load_height),
        (receipt, evidence.clone())
    );
    assert_eq!(ledger_rows(&setup), rows);
    let retry = execute(&mut setup, 43, unload, None);
    assert_ne!(retry, unload_transaction);
    let stale = load_command(&input, &charges.load, setup.recipients[1].clone(), 250);
    execute(
        &mut setup,
        41,
        stale,
        Some(ledger_error("permanent replay key conflicts")),
    );
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [892, 0, 8, 100]);
    setup = replay_into_fresh_state(setup);
    assert_eq!(ledger_rows(&setup), rows);
    require_conservation(&setup, [892, 0, 8, 100]);
    assert_eq!(
        load_evidence(&setup, &input, &charges.load, load_height),
        (receipt, evidence.clone())
    );

    let output = selected("KAGEMUSHA_EXECUTED_CHARGE_CONTINUATION_OUTPUT");
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory.create(&output).unwrap();
    let mut records = vec![
        bounded_original(&output, "charged-load-receipt.norito", &receipt.to_canonical_bytes().unwrap(),
            iroha_data_model::isi::kagemusha_wallet::load_finality::KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1),
        bounded_original(&output, "charged-load-finality.norito", &evidence.to_canonical_bytes().unwrap(),
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1),
        publish(&output, "unload-payout.norito", &payout_bytes),
    ];
    let mut verifier = native(&setup);
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
    publish(&output, "result.json", &norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.executed-charge-continuation.v1","origin":"core",
        "producer_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_CHARGE_RESULT_SHA256"))),
        "target_sha256":(hex::encode(input.target_sha256)),
        "initial_receipt_sha256":(hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"))),
        "scheme_id":(hex::encode(input.scheme.scheme_id())),"manifest_digest":(hex::encode(input.manifest)),
        "charged_load_height":load_height,"unload_height":unload_height,"last_certified_height":(setup.chain.height()),
        "load_transaction_hash":(hex::encode(load_transaction)),"unload_transaction_hash":(hex::encode(unload_transaction)),
        "balances_atomic_units":["892","0","8","100"],"certified_fresh_state_replay":true,
        "scope":"One actual ordinary Core chain: initial Load100, charged Load100+3, then genuine pending Unload100 split95+5. Full balances and permanent payout/issuance rows survive fresh signed retries and two fresh-State certified replays. Genuine native finality and counted Load event are exported for the same retained wallet. Test-signed committee, not four live peers; no transport, disk/power-loss, native Unload acknowledgement, physical or release qualification.",
        "originals":records,
    })).unwrap());
    File::open(&output).unwrap().sync_all().unwrap();
}
