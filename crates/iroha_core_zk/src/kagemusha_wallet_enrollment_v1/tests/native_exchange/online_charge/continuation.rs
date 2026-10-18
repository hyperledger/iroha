//! Consume the actual later charged Load in the same retained dedicated A incarnation.
//!
//! Full prefix verification authenticates the ordinary charge and Unload ordering; native
//! Load admission independently verifies the compact BLS certificate and counted event.
//! TODO: Compile and execute after the paired Core continuation; no physical claim is made.

use super::*;
use crate::kagemusha_wallet_state_v1::LEDGER_PROOF_MAX_BYTES_V1;
use iroha_data_model::{
    isi::kagemusha_wallet::{
        KagemushaWalletLoadChargeV1, load_finality::verify_finalized_kagemusha_wallet_load_event_v1,
    },
    sumeragi_finality::{
        SumeragiCommitCertificateV1, SumeragiFinalityProof, VerifiedSumeragiBlock,
    },
    transaction::Executable,
};
use std::collections::BTreeSet;

#[path = "continuation/unload_confirmation.rs"]
mod unload_confirmation;

fn digest(value: &norito::json::Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    let bytes: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
    assert_ne!(bytes, [0; 32]);
    assert_eq!(hex::encode(bytes), text);
    bytes
}

fn inventory(value: &norito::json::Value, expected: &[String]) {
    let rows = value["originals"].as_array().unwrap();
    assert_eq!(rows.len(), expected.len());
    let names = rows
        .iter()
        .map(|row| {
            assert!(row["bytes"].as_u64().is_some_and(|length| length > 0));
            digest(&row["sha256"]);
            row["name"].as_str().unwrap().to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, expected.iter().cloned().collect::<BTreeSet<_>>());
}

fn evidence_inventory(value: &norito::json::Value) -> (u64, u64, u64) {
    assert_eq!(
        value["schema"].as_str(),
        Some("iroha.kagemusha.executed-charge-continuation.v1")
    );
    assert_eq!(value["origin"].as_str(), Some("core"));
    let load = value["charged_load_height"].as_u64().unwrap();
    let unload = value["unload_height"].as_u64().unwrap();
    let through = value["last_certified_height"].as_u64().unwrap();
    assert!((6..=64).contains(&load) && load < unload && unload <= through && through <= 64);
    let expected = [
        "charged-load-receipt.norito",
        "charged-load-finality.norito",
        "unload-payout.norito",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain((1..=through).map(|height| format!("native-proof-{height}.norito")))
    .collect::<Vec<_>>();
    inventory(value, &expected);
    (load, unload, through)
}

fn original(root: &Path, value: &norito::json::Value, name: &str, maximum: usize) -> Vec<u8> {
    target_original(
        root,
        &norito::json!({"files":(value["originals"].clone())}),
        name,
        maximum,
    )
}

fn require_success(
    block: &VerifiedSumeragiBlock,
    hash: [u8; 32],
    payer: &AccountId,
    expected: &KagemushaWalletLedgerV1,
) {
    let transactions = block.block().external_transactions().collect::<Vec<_>>();
    assert_eq!(
        transactions.len(),
        1,
        "one original ordinary transaction at this selected height"
    );
    let transaction = transactions[0];
    assert_eq!(*transaction.hash().as_ref(), hash);
    assert_eq!(transaction.authority(), payer);
    assert!(block.block().output_error(0).is_none());
    let Executable::Instructions(instructions) = transaction.instructions() else {
        panic!("direct ordinary wallet instruction")
    };
    assert_eq!(instructions.len(), 1);
    let actual = instructions[0]
        .as_any()
        .downcast_ref::<KagemushaWalletLedgerV1>()
        .unwrap();
    assert_eq!(
        norito::encode_canonical(actual).unwrap(),
        norito::encode_canonical(expected).unwrap()
    );
}

#[test]
fn charged_load_continuation_inventory_rejects_missing_roles_and_reordered_heights() {
    let rows = [
        "charged-load-receipt.norito",
        "charged-load-finality.norito",
        "unload-payout.norito",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain((1..=12).map(|h| format!("native-proof-{h}.norito")))
    .map(|name| norito::json!({"name":name,"bytes":1,"sha256":(hex::encode([1;32]))}))
    .collect::<Vec<_>>();
    let valid = norito::json!({"schema":"iroha.kagemusha.executed-charge-continuation.v1","origin":"core","charged_load_height":7,"unload_height":8,"last_certified_height":12,"originals":rows});
    assert_eq!(evidence_inventory(&valid), (7, 8, 12));
    for mode in 0..7 {
        let mut changed = valid.clone();
        if mode < 3 {
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
        } else {
            let (field, value) = match mode {
                3 => ("charged_load_height", 8.into()),
                4 => ("unload_height", 13.into()),
                5 => ("last_certified_height", 65.into()),
                _ => ("origin", "network".into()),
            };
            changed.as_object_mut().unwrap().insert(field.into(), value);
        }
        assert!(std::panic::catch_unwind(|| evidence_inventory(&changed)).is_err());
    }
    assert!(std::panic::catch_unwind(|| digest(&norito::json!("01"))).is_err());
}

#[test]
#[ignore = "requires exact same dedicated A after quoted Unload and genuine same-chain charged Load/Unload Core evidence"]
fn actual_same_a_absorbs_charged_load_once_after_pending_unload_with_restart() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CHARGED_LOAD_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let scheme = &f.config.scheme;
    let producer_path = selected_path("KAGEMUSHA_NATIVE_CHARGE_RESULT");
    let producer_bytes = read_pin(
        &producer_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_CHARGE_RESULT_SHA256"),
    );
    let producer: norito::json::Value = norito::json::from_slice(&producer_bytes).unwrap();
    assert_eq!(
        producer["schema"].as_str(),
        Some("iroha.kagemusha.native-online-charge-result.v1")
    );
    assert_eq!(producer["variant"].as_str(), Some("online-charges"));
    assert_eq!(producer["source_pins"], source_pins());
    assert_eq!(
        producer["executed_ledger_setup_sha256"].as_str(),
        Some(setup.manifest_sha256.as_str())
    );
    assert_eq!(digest(&producer["scheme_id"]), scheme.scheme_id());
    assert_eq!(
        digest(&producer["manifest_digest"]),
        sources.qualified.installation().1
    );
    assert_eq!(
        producer["target_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256").as_str())
    );
    assert_eq!(
        producer["receipt_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256").as_str())
    );
    inventory(
        &producer,
        &[
            "regulatory-certificate.norito",
            "load-quote.norito",
            "stale-load-quote.norito",
            "exhausting-load-quote.norito",
            "unload-quote.norito",
            "stale-unload-quote.norito",
            "unload-claim.norito",
        ]
        .map(str::to_owned),
    );
    let producer_root = producer_path.parent().unwrap();
    let certificate: KagemushaWalletSignerCertificateV1 = decode(&original(
        producer_root,
        &producer,
        "regulatory-certificate.norito",
        KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
    ));
    certificate.verify(scheme).unwrap();
    assert_eq!(
        certificate.body.role,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy
    );
    let quote = KagemushaWalletChargeQuoteV1::decode_canonical(
        &original(
            producer_root,
            &producer,
            "load-quote.norito",
            KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1,
        ),
        &scheme.scheme_id(),
    )
    .unwrap();
    quote.verify(scheme, &certificate).unwrap();
    let claim_bytes = original(
        producer_root,
        &producer,
        "unload-claim.norito",
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
    );
    let claim =
        KagemushaWalletUnloadClaimV1::decode_canonical(&claim_bytes, &scheme.scheme_id()).unwrap();
    let paid = claim.verify(scheme).unwrap();
    assert_eq!(
        (paid.amount, paid.account_payout, paid.online_charge),
        (100, 95, 5)
    );
    sources
        .installed
        .verifier()
        .verify_package_proofs(&claim.package, MemoryBudget::DEFAULT)
        .unwrap();

    let target_path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &target_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    assert_eq!(target["variant"].as_str(), Some("online-charges"));
    let public = target_path.parent().unwrap();
    let frames = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let initial_command: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames, &initial_command);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme.scheme_id()).unwrap();
    assert_eq!(
        credential.body.payment_key,
        public_key(&signing_key(CHARGE_KEY_SEED))
    );
    assert_eq!(credential, claim.credential);
    assert_eq!(
        credential.body.wallet_id,
        digest(&producer["payer_wallet_id"])
    );
    assert_eq!(
        credential.credential_digest(),
        digest(&producer["payer_credential_digest"])
    );
    assert_eq!(claim.account, setup.accounts[0]);
    assert_eq!(quote.body.asset_digest, f.asset.asset_digest());
    assert_eq!(
        quote.body.beneficiary_account_digest,
        kagemusha_wallet_account_digest_v1(&setup.accounts[2]).unwrap()
    );
    quote
        .require_terms(
            KagemushaWalletChargeKindV1::Load,
            &credential.body.wallet_id,
            1,
            100,
            3,
        )
        .unwrap();

    let capture_path = selected_path("KAGEMUSHA_EXECUTED_CHARGE_CONTINUATION");
    let capture_bytes = read_pin(
        &capture_path,
        32 << 10,
        &env_pin("KAGEMUSHA_EXECUTED_CHARGE_CONTINUATION_SHA256"),
    );
    let capture: norito::json::Value = norito::json::from_slice(&capture_bytes).unwrap();
    let (load_height, unload_height, through) = evidence_inventory(&capture);
    assert_eq!(
        capture["producer_sha256"].as_str(),
        Some(sha(&producer_bytes).as_str())
    );
    for field in ["target_sha256", "scheme_id", "manifest_digest"] {
        assert_eq!(capture[field], producer[field]);
    }
    assert_eq!(
        capture["initial_receipt_sha256"],
        producer["receipt_sha256"]
    );
    let root = capture_path.parent().unwrap();
    let receipt_bytes = original(
        root,
        &capture,
        "charged-load-receipt.norito",
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
    );
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap();
    let finality_bytes = original(
        root,
        &capture,
        "charged-load-finality.norito",
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
    );
    let finality = KagemushaWalletLoadFinalityV1::decode_canonical(&finality_bytes).unwrap();
    assert_eq!(
        (
            receipt.scheme_id,
            receipt.asset_digest,
            receipt.wallet_id,
            receipt.payer_account_digest
        ),
        (
            scheme.scheme_id(),
            f.asset.asset_digest(),
            credential.body.wallet_id,
            kagemusha_wallet_account_digest_v1(&f.account).unwrap()
        )
    );
    assert_eq!(
        (
            receipt.ordinal,
            receipt.amount,
            receipt.online_charge,
            receipt.block_height,
            receipt.request_id
        ),
        (1, 100, 3, load_height, [249; 32])
    );
    receipt.require_charge_quote(Some(&quote)).unwrap();
    assert_eq!(receipt.ledger_debit().unwrap(), 103);
    assert_eq!(
        receipt.transaction_hash,
        digest(&capture["load_transaction_hash"])
    );
    finality.verify(&sources.genesis, &receipt).unwrap();
    let payout: KagemushaWalletPayoutRecordV1 =
        decode(&original(root, &capture, "unload-payout.norito", 4096));
    assert_eq!(
        payout.key,
        KagemushaWalletPayoutKeyV1::Unload(paid.nullifier)
    );
    assert_eq!(
        (payout.source, payout.amount, payout.transaction),
        (
            paid.package,
            100,
            digest(&capture["unload_transaction_hash"])
        )
    );
    let initial_receipt_bytes = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_RECEIPT"),
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
    );
    let initial_receipt =
        KagemushaWalletLoadReceiptV1::decode_canonical(&initial_receipt_bytes).unwrap();
    let initial_finality = KagemushaWalletLoadFinalityV1::decode_canonical(&read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_FINALITY"),
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_FINALITY_SHA256"),
    ))
    .unwrap();
    assert!(initial_receipt.block_height >= 2 && initial_receipt.block_height < load_height);
    assert_eq!(
        (
            initial_receipt.wallet_id,
            initial_receipt.ordinal,
            initial_receipt.amount,
            initial_receipt.online_charge,
            initial_receipt.request_id
        ),
        (credential.body.wallet_id, 0, 100, 0, LOAD_ID)
    );
    initial_finality
        .verify(&sources.genesis, &initial_receipt)
        .unwrap();
    let expected_load = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: credential.body.wallet_id,
            asset: f.asset.asset_digest(),
            ordinal: 1,
            request_id: [249; 32],
            amount: 100,
            charge: Some(KagemushaWalletLoadChargeV1 {
                quote: quote.to_canonical_bytes().unwrap(),
                beneficiary: setup.accounts[2].clone(),
            }),
        },
    );
    let expected_unload = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Unload(claim_bytes.clone()),
    );
    let mut verifier = (*sources.genesis).clone();
    for height in 1..=through {
        let proof: SumeragiFinalityProof = decode(&original(
            root,
            &capture,
            &format!("native-proof-{height}.norito"),
            LEDGER_PROOF_MAX_BYTES_V1,
        ));
        assert_eq!(proof.height(), height);
        assert_eq!(proof.committee.len(), 4);
        let block = verifier.verify(&proof).unwrap();
        if height > 1 {
            let qc: iroha_sumeragi::message::Qc =
                decode(block.block().commit_certificate().unwrap().commit_qc());
            assert_eq!(qc.signers.count_ones(), 3);
        }
        if height == initial_receipt.block_height {
            let selected = SumeragiCommitCertificateV1::from_verified(&block).unwrap();
            assert_eq!(
                initial_finality.certificate.consensus_header,
                selected.consensus_header
            );
            assert_eq!(
                initial_finality.certificate.result_preimage,
                selected.result_preimage
            );
            require_success(
                &block,
                initial_receipt.transaction_hash,
                &f.account,
                &initial_command,
            );
            verify_finalized_kagemusha_wallet_load_event_v1(
                &block,
                &initial_finality.event_proof,
                sources.genesis.initial_epoch().network_id,
                sources.genesis.chain_id(),
                &initial_receipt,
            )
            .unwrap();
        }
        if height == load_height {
            // The compact envelope independently verified above must name the same certified
            // header/result. Different valid exact-quorum signature witnesses are permitted.
            let selected = SumeragiCommitCertificateV1::from_verified(&block).unwrap();
            assert_eq!(
                finality.certificate.consensus_header,
                selected.consensus_header
            );
            assert_eq!(
                finality.certificate.result_preimage,
                selected.result_preimage
            );
            require_success(&block, receipt.transaction_hash, &f.account, &expected_load);
            verify_finalized_kagemusha_wallet_load_event_v1(
                &block,
                &finality.event_proof,
                sources.genesis.initial_epoch().network_id,
                sources.genesis.chain_id(),
                &receipt,
            )
            .unwrap();
        }
        if height == unload_height {
            require_success(
                &block,
                payout.transaction,
                &setup.accounts[1],
                &expected_unload,
            );
        }
    }
    // Manifest balances are observations; the Core producer asserts supply and every bucket.
    assert_eq!(
        capture["balances_atomic_units"],
        norito::json!(["892", "0", "8", "100"])
    );

    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    let mut a = sources.open(&device, &f, &frames);
    let before = a.snapshot().unwrap();
    let epoch = a.epoch_progress().unwrap();
    assert_eq!(before.head, digest(&producer["a_final_head"]));
    assert_eq!(before.head, claim.package.statement.successor.value);
    assert_eq!(before.sequence, claim.package.statement.sequence);
    assert_eq!(claim.package.statement.next_load, 1);
    assert_eq!(
        before.sequence.to_string(),
        producer["a_final_sequence"].as_str().unwrap()
    );
    assert_eq!(before.credential_digest, credential.credential_digest());
    assert_eq!(
        (
            before.owned_balance,
            before.known_burned_total,
            before.folded_balance
        ),
        (0, 0, Some(0))
    );
    assert_eq!(epoch.epoch, producer["finality_epoch"].as_u64().unwrap());
    assert!(epoch.first_height <= load_height && through <= epoch.boundary_height);
    assert_eq!(finality.certificate.epoch_id().unwrap(), epoch.epoch);
    let beneficiary = norito::encode_canonical(&setup.accounts[2]).unwrap();
    let unload_request = digest(&producer["unload_request_id"]);
    assert_eq!(
        a.unload_claim_bytes(&unload_request, Some(&beneficiary))
            .unwrap(),
        claim_bytes
    );
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        signatures, 0,
        "opening existing custody must not payment-sign"
    );

    let mut changed = receipt;
    changed.online_charge += 1;
    let mut rebound = finality.clone();
    rebound.receipt_digest = changed.receipt_digest().unwrap();
    for (id, evidence, reason) in [(243, finality.clone(), "binding"), (244, rebound, "event")] {
        let attempted = action(
            id,
            OperationActionV1::Load {
                receipt: changed.to_canonical_bytes().unwrap(),
                finality: evidence.to_canonical_bytes().unwrap(),
            },
        );
        let OperationActionV1::Load { receipt, finality } = &attempted.action else {
            unreachable!()
        };
        retain_bounded(
            &output,
            &format!("refused-{id}-receipt.norito"),
            receipt,
            KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        );
        retain_bounded(
            &output,
            &format!("refused-{id}-finality.norito"),
            finality,
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        );
        let error = a.execute(attempted).unwrap_err();
        match reason {
            "binding" => assert!(matches!(
                error,
                state::Error::Invalid("Load original binding")
            )),
            _ => assert!(matches!(error, state::Error::Proof("Load native finality"))),
        }
        assert_eq!(a.snapshot().unwrap(), before);
        assert_eq!(a.epoch_progress().unwrap(), epoch);
        assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    }
    let load = action(
        242,
        OperationActionV1::Load {
            receipt: receipt_bytes.clone(),
            finality: finality_bytes.clone(),
        },
    );
    let online_receipt = retain_bounded(
        &output,
        "charged-load-receipt.norito",
        &receipt_bytes,
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
    );
    let online_finality = retain_bounded(
        &output,
        "charged-load-finality.norito",
        &finality_bytes,
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
    );
    let loaded = complete(a.execute(load.clone()).unwrap());
    let package_original = retain_bounded(
        &output,
        "charged-load-package.norito",
        &loaded,
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let package = KagemushaWalletPackageV1::decode_canonical(&loaded, &scheme.scheme_id()).unwrap();
    assert_eq!(
        package.statement.effect,
        KagemushaWalletEffectV1::Load {
            receipt_digest: receipt.receipt_digest().unwrap(),
            load_ordinal: 1,
            amount: 100,
            online_charge: 3
        }
    );
    assert_eq!(package.statement.next_load, 2);
    assert_eq!(package.statement.sequence, before.sequence + 1);
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, MemoryBudget::DEFAULT)
        .unwrap();
    let after_signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(after_signatures, signatures + 1);
    assert_eq!(complete(a.execute(load.clone()).unwrap()), loaded);
    fold(&mut a);
    let after = a.snapshot().unwrap();
    assert_eq!(
        (
            after.owned_balance,
            after.known_burned_total,
            after.folded_balance
        ),
        (100, 0, Some(100))
    );
    assert_eq!(a.epoch_progress().unwrap(), epoch);
    // The Unload claim remains its original object; a later Load does not rewrite that spend.
    assert_eq!(
        a.unload_claim_bytes(&unload_request, Some(&beneficiary))
            .unwrap(),
        claim_bytes
    );
    for _ in 0..2 {
        let mut duplicate = load.clone();
        duplicate.request_id = [245; 32];
        assert!(matches!(
            a.execute(duplicate),
            Err(state::Error::Invalid("G1 validation"))
        ));
        let mut conflicting = load.clone();
        let OperationActionV1::Load { receipt, .. } = &mut conflicting.action else {
            unreachable!()
        };
        *receipt = changed.to_canonical_bytes().unwrap();
        assert!(matches!(
            a.execute(conflicting),
            Err(state::Error::OperationConflict)
        ));
        assert_eq!(complete(a.execute(load.clone()).unwrap()), loaded);
        assert_eq!(a.snapshot().unwrap(), after);
        assert_eq!(a.epoch_progress().unwrap(), epoch);
        assert_eq!(
            device.platform.with(|state| state.sign_calls),
            after_signatures
        );
        drop(a);
        a = sources.open(&device, &f, &frames);
        assert_eq!(a.snapshot().unwrap(), after);
        assert_eq!(complete(a.execute(load.clone()).unwrap()), loaded);
    }
    assert_eq!(
        a.unload_claim_bytes(&unload_request, Some(&beneficiary))
            .unwrap(),
        claim_bytes
    );
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        after_signatures
    );
    publish(&output.join("result.json"), &norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.native-charged-load-absorption.v1","origin":"core",
        "producer_sha256":(sha(&producer_bytes)),"execution_sha256":(sha(&capture_bytes)),"target_sha256":(sha(&target_bytes)),
        "source_pins":(source_pins()),"native_binary_sha256":(executable_hash()),
        "load_height":load_height,"unload_height":unload_height,"last_certified_height":through,
        "payer_head":(hex::encode(after.head)),"payer_sequence":(after.sequence.to_string()),"native_balance_atomic_units":"100","native_next_load":"2",
        "ledger_balances_atomic_units":["892","0","8","100"],"finality_epoch":(epoch.epoch),
        "new_payment_signatures":1,"exact_retry_after_restart":true,"original_pending_unload_retained":true,
        "scope":"Same dedicated retained A consumes the genuine later ordinal1 charged Load after its Unload100 has been paid on that same authenticated chain. Native adds net100, not online debit103, once. Altered charge with original/rebound digest is refused before payment signing; exact completion and historical Unload originals survive reopen, while new-request replay and changed original are refused. Native uses production proofs/finality/custody with simulated hardware. Core balances are asserted by the independently pinned ordinary execution producer; this is not four live peers, native Unload acknowledgement, hardware/power-loss or release qualification.",
        "complete_online_originals":[online_receipt,online_finality,package_original],
    })).unwrap());
}
