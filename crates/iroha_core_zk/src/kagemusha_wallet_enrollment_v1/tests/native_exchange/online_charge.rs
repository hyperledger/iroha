//! Genuine online-charge artifacts from a fresh dedicated native incarnation.
//!
//! TODO: Compile and execute with current-source admitted artifacts. Engineering signer and
//! hardware fixtures remain explicit; only ordinary later ledger execution pays any charge.

use super::*;

#[path = "online_charge/continuation.rs"]
mod continuation;
use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};

const CHARGE_KEY_SEED: u8 = 111;
const REGULATORY_KEY_SEED: u8 = 113;

#[test]
#[ignore = "requires the genuine complete52 source grant; exports a target, never a finalized receipt"]
fn export_actual_online_charge_target_with_dedicated_custody() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CHARGE_TARGET_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let device = HostDevice::create(&output.join("wallet-a"), CHARGE_KEY_SEED);
    let frames = device.enroll(&f);
    let mut wallet = sources.open(&device, &f, &frames);
    let bootstrap = complete(wallet.bootstrap().unwrap());
    assert_eq!(complete(wallet.bootstrap().unwrap()), bootstrap);
    let activation = wallet.activation().unwrap();
    assert_eq!(wallet.activation().unwrap(), activation);
    fold(&mut wallet);
    let snapshot = wallet.snapshot().unwrap();
    assert_eq!((snapshot.sequence, snapshot.owned_balance), (0, 0));
    let instruction = KagemushaWalletLedgerV1::new(
        snapshot.scheme_id,
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: snapshot.wallet_id,
            asset: f.asset.asset_digest(),
            ordinal: 0,
            request_id: LOAD_ID,
            amount: LOAD_AMOUNT,
            charge: None,
        },
    );
    let public = output.join("public-target");
    private_dir(&public);
    let mut records = Vec::new();
    for (name, bytes) in FRAME_NAMES.into_iter().zip(&frames).chain([
        ("bootstrap.norito", &bootstrap),
        ("activation.norito", &activation),
        (
            "issue-load.norito",
            &norito::encode_canonical(&instruction).unwrap(),
        ),
    ]) {
        publish(&public.join(name), bytes);
        records
            .push(norito::json!({ "name": name, "bytes": (bytes.len()), "sha256": (sha(bytes)) }));
    }
    drop(wallet);
    device.save_simulator();
    let manifest = norito::json!({
        "schema": TARGET_SCHEMA,
        "variant": "online-charges",
        "scope": "Dedicated online-charge native A with real host storage and proofs; simulated payment hardware and engineering issuer. Target DATA is not a finalized receipt or settlement verdict.",
        "source_pins": (source_pins()),
        "sealed_originals": (source_reuse::locator(&sources.originals)),
        "executed_ledger_setup_sha256": (setup.manifest_sha256),
        "native_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "native_binary_sha256": (executable_hash()),
        "native_chain_id": (sources.genesis.chain_id()),
        "native_instance": (hex::encode(sources.genesis.instance().0)),
        "native_initial_epoch_sha256": (sha(&norito::encode_canonical(sources.genesis.initial_epoch()).unwrap())),
        "scheme_id": (hex::encode(snapshot.scheme_id)),
        "manifest_digest": (hex::encode(sources.qualified.installation().1)),
        "wallet_id": (hex::encode(snapshot.wallet_id)),
        "asset_digest": (hex::encode(f.asset.asset_digest())),
        "payer_account_digest": (hex::encode(kagemusha_wallet_account_digest_v1(&f.account).unwrap())),
        "request_id": (hex::encode(LOAD_ID)),
        "ordinal": "0", "amount": "100", "online_charge": "0",
        "charge_quote": (hex::encode([0_u8; 32])),
        "files": records,
    });
    let bytes = norito::json::to_vec(&manifest).unwrap();
    assert!(bytes.len() <= TARGET_MAX);
    publish(&public.join("target.json"), &bytes);
    eprintln!(
        "NATIVE_LOAD_TARGET path={} sha256={} finalized_receipt=false",
        public.join("target.json").display(),
        sha(&bytes)
    );
}

fn certificate(scheme: &KagemushaWalletSchemeV1) -> KagemushaWalletSignerCertificateV1 {
    assert_eq!(scheme.scheme_root_key, public_key(&signing_key(17)));
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        key: public_key(&signing_key(REGULATORY_KEY_SEED)),
        serial: 3,
    };
    let signature: P256Signature = signing_key(17).sign(&body.signing_message());
    KagemushaWalletSignerCertificateV1::sign(
        body,
        scheme,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap()
}

fn quote(
    credential: &KagemushaWalletCredentialV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    beneficiary: &AccountId,
    terms: (KagemushaWalletChargeKindV1, u128, u128, u128),
) -> KagemushaWalletChargeQuoteV1 {
    let (kind, ordinal, net_amount, online_charge) = terms;
    let body = KagemushaWalletChargeQuoteBodyV1 {
        version: 1,
        scheme_id: credential.body.scheme_id,
        asset_digest: credential.body.asset_digest,
        wallet_id: credential.body.wallet_id,
        kind,
        ordinal,
        net_amount,
        online_charge,
        beneficiary_account_digest: kagemusha_wallet_account_digest_v1(beneficiary).unwrap(),
        issued_at_ms: 1,
        signer_certificate: certificate.certificate_digest(),
    };
    let signature: P256Signature = signing_key(REGULATORY_KEY_SEED).sign(&body.signing_message());
    KagemushaWalletChargeQuoteV1::sign(
        body,
        certificate,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap()
}

fn retain_bounded(output: &Path, name: &str, bytes: &[u8], maximum: usize) -> norito::json::Value {
    // Preserve the complete online frame and measurement before any bound assertion.
    publish(&output.join(name), bytes);
    let row = norito::json!({"name":name,"bytes":(bytes.len()),"sha256":(sha(bytes)),"maximum_bytes":maximum,"within_bound":(bytes.len() <= maximum)});
    publish(
        &output.join(format!("{name}.measurement.json")),
        &norito::json::to_vec(&row).unwrap(),
    );
    assert!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "complete online frame bound: {name}"
    );
    row
}

#[test]
#[ignore = "requires fresh dedicated online-charge A custody and genuine current-source Load receipt/proof; consumes A100 to quoted Unload100/charge5"]
fn actual_online_charge_unload_with_retained_quotes_and_restart() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CHARGE_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let scheme = &f.config.scheme;
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
    let command: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames, &command);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme.scheme_id()).unwrap();
    assert_eq!(
        credential.body.payment_key,
        public_key(&signing_key(CHARGE_KEY_SEED)),
        "fresh dedicated incarnation; ABC and fee custody cannot be reused"
    );
    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    let mut a = sources.open(&device, &f, &frames);
    let initial = a.snapshot().unwrap();
    assert_eq!((initial.sequence, initial.owned_balance), (0, 0));
    let signatures = device.platform.with(|state| state.sign_calls);
    let (signed_activation, activation) = load::confirm_existing_activation(&mut a, &sources);
    drop(a);
    let mut a = sources.open(&device, &f, &frames);
    assert_eq!(
        a.confirm_ledger_activation(&signed_activation).unwrap(),
        activation
    );
    assert_eq!(a.snapshot().unwrap(), initial);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    let receipt_bytes = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_RECEIPT"),
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
    );
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap();
    assert_eq!(
        (
            receipt.wallet_id,
            receipt.ordinal,
            receipt.amount,
            receipt.online_charge,
            receipt.charge_quote
        ),
        (credential.body.wallet_id, 0, 100, 0, [0; 32])
    );
    let finality = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_FINALITY"),
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_FINALITY_SHA256"),
    );
    let load = action(
        240,
        OperationActionV1::Load {
            receipt: receipt_bytes,
            finality,
        },
    );
    let loaded = complete(a.execute(load.clone()).unwrap());
    assert_eq!(complete(a.execute(load).unwrap()), loaded);
    fold(&mut a);
    assert_eq!(
        (
            a.snapshot().unwrap().owned_balance,
            a.snapshot().unwrap().folded_balance
        ),
        (100, Some(100))
    );

    let certificate = certificate(scheme);
    certificate.verify(scheme).unwrap();
    let beneficiary = &setup.accounts[2];
    let load_quote = quote(
        &credential,
        &certificate,
        beneficiary,
        (KagemushaWalletChargeKindV1::Load, 1, 100, 3),
    );
    let stale_load_quote = quote(
        &credential,
        &certificate,
        beneficiary,
        (KagemushaWalletChargeKindV1::Load, 0, 100, 3),
    );
    let exhausting_load_quote = quote(
        &credential,
        &certificate,
        beneficiary,
        (KagemushaWalletChargeKindV1::Load, 1, 900, 3),
    );
    let unload_quote = quote(
        &credential,
        &certificate,
        beneficiary,
        (KagemushaWalletChargeKindV1::Unload, 0, 100, 5),
    );
    let stale_unload_quote = quote(
        &credential,
        &certificate,
        beneficiary,
        (KagemushaWalletChargeKindV1::Unload, 1, 100, 5),
    );
    for quote in [
        &load_quote,
        &stale_load_quote,
        &exhausting_load_quote,
        &unload_quote,
        &stale_unload_quote,
    ] {
        quote.verify(scheme, &certificate).unwrap();
    }
    let charge = state::ChargeOriginalsV1 {
        quote: unload_quote.to_canonical_bytes().unwrap(),
        certificates: norito::encode_canonical(&KagemushaWalletCertificateSetV1 {
            certificates: vec![certificate],
        })
        .unwrap(),
    };
    let unload = action(
        241,
        OperationActionV1::Unload {
            amount: 100,
            charge: Some(charge),
        },
    );
    let unloaded = complete(a.execute(unload.clone()).unwrap());
    let after_unload_signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(a.execute(unload.clone()).unwrap()), unloaded);
    let beneficiary_original = norito::encode_canonical(beneficiary).unwrap();
    let claim_bytes = a
        .unload_claim_bytes(&unload.request_id, Some(&beneficiary_original))
        .unwrap();
    let record = retain_bounded(
        &output,
        "unload-claim.norito",
        &claim_bytes,
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
    );
    let claim =
        KagemushaWalletUnloadClaimV1::decode_canonical(&claim_bytes, &scheme.scheme_id()).unwrap();
    assert_eq!(claim.account, setup.accounts[0]);
    assert_eq!(norito::encode_canonical(&claim.package).unwrap(), unloaded);
    let paid = claim.verify(scheme).unwrap();
    assert_eq!(
        (paid.amount, paid.account_payout, paid.online_charge),
        (100, 95, 5)
    );
    assert_eq!(paid.charge_quote, unload_quote.charge_quote_digest());
    assert_eq!(claim.package.statement.next_load, 1);
    assert_eq!(claim.package.statement.enabled_controls, 0);
    let lineage_measurement = message_census::record(
        &output,
        "unload-predecessor-lineage",
        KagemushaWalletMessageV1::Lineage {
            lineage: KagemushaWalletLineageMessageV1::new(
                claim.package.lineage.lineage().unwrap().clone(),
            ),
        },
    );
    sources
        .installed
        .verifier()
        .verify_package_proofs(&claim.package, None, MemoryBudget::DEFAULT)
        .unwrap();
    fold(&mut a);
    let final_snapshot = a.snapshot().unwrap();
    assert_eq!(
        (
            final_snapshot.owned_balance,
            final_snapshot.known_burned_total,
            final_snapshot.folded_balance
        ),
        (0, 0, Some(0))
    );
    drop(a);
    let mut a = sources.open(&device, &f, &frames);
    assert_eq!(a.snapshot().unwrap(), final_snapshot);
    assert_eq!(complete(a.execute(unload.clone()).unwrap()), unloaded);
    assert_eq!(
        a.unload_claim_bytes(&unload.request_id, Some(&beneficiary_original))
            .unwrap(),
        claim_bytes
    );
    assert!(a.unload_claim_bytes(&unload.request_id, None).is_err());
    assert!(
        a.unload_claim_bytes(
            &unload.request_id,
            Some(&norito::encode_canonical(&setup.accounts[1]).unwrap())
        )
        .is_err()
    );
    assert_eq!(a.snapshot().unwrap(), final_snapshot);
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        after_unload_signatures
    );
    let mut originals = vec![record];
    originals.push(retain_bounded(
        &output,
        "regulatory-certificate.norito",
        &norito::encode_canonical(&certificate).unwrap(),
        KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
    ));
    for (name, quote) in [
        ("load-quote.norito", load_quote),
        ("stale-load-quote.norito", stale_load_quote),
        ("exhausting-load-quote.norito", exhausting_load_quote),
        ("unload-quote.norito", unload_quote),
        ("stale-unload-quote.norito", stale_unload_quote),
    ] {
        originals.push(retain_bounded(
            &output,
            name,
            &norito::encode_canonical(&quote).unwrap(),
            KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1,
        ));
    }
    let result = norito::json!({
        "schema":"iroha.kagemusha.native-online-charge-result.v1", "variant":"online-charges",
        "target_sha256":(sha(&target_bytes)), "receipt_sha256":(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256")),
        "scheme_id":(hex::encode(scheme.scheme_id())), "manifest_digest":(hex::encode(sources.qualified.installation().1)),
        "source_pins":(source_pins()), "executed_ledger_setup_sha256":(setup.manifest_sha256), "native_binary_sha256":(executable_hash()),
        "payer_wallet_id":(hex::encode(credential.body.wallet_id)), "unload_request_id":(hex::encode(unload.request_id)),
        "a_final_head":(hex::encode(final_snapshot.head)), "a_final_sequence":(final_snapshot.sequence.to_string()),
        "payer_credential_digest":(hex::encode(final_snapshot.credential_digest)), "finality_epoch":(a.epoch_progress().unwrap().epoch),
        "gross_unload":"100", "online_unload_charge":"5", "account_payout":"95", "native_remaining":"0",
        "scope":"Genuine dedicated A Load and quoted Unload with exact retained claim and restart; simulated hardware and root-authenticated engineering RegulatoryPolicy signer. Online ledger payout and charged-Load debit are separate ordinary Core tests. No peer Send fee or enabled offline control is used; no network, physical or release qualification.",
        "originals":originals,"complete_envelopes":[lineage_measurement],
    });
    publish(
        &output.join("result.json"),
        &norito::json::to_vec(&result).unwrap(),
    );
}
