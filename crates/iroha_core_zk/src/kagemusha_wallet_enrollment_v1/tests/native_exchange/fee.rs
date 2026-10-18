//! Separate genuine fee-bearing Send, historical Request custody, and ArchiveReceive replay.
//!
//! Export a NEW dedicated target, fund it through ordinary Core execution, then run this
//! producer on the SAME retained custody. Never clone or reuse the consumed zero-fee ABC A.
//! The distinct simulated key and sequence-zero check reject that existing ABC incarnation.
//! Real installed proofs and signatures are required; hardware and issuer remain explicit
//! engineering fixtures. Core fee payout consumes the three exact public originals separately.
//! TODO: Compile and execute this candidate with fresh current-source full-catalog artifacts.

use super::*;
use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};

const FEE_KEY_SEED: u8 = 101;
const REGULATORY_KEY_SEED: u8 = 103;

#[test]
#[ignore = "requires the genuine complete22 source grant; exports a target, never a finalized receipt"]
fn export_actual_fee_load_target_with_separate_native_custody() {
    let output = fresh_output("KAGEMUSHA_NATIVE_FEE_TARGET_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let device = HostDevice::create(&output.join("wallet-a"), FEE_KEY_SEED);
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
        "variant": "fee97-plus3",
        "scope": "Actual native A with real host storage and proofs; simulated payment hardware and engineering issuer. Target DATA is not a finalized receipt or settlement verdict.",
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

fn fee_terms(
    scheme: &KagemushaWalletSchemeV1,
    asset: [u8; 32],
    beneficiary: [u8; 32],
) -> (
    KagemushaWalletSignerCertificateV1,
    KagemushaWalletFeeScheduleV1,
) {
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        key: public_key(&signing_key(REGULATORY_KEY_SEED)),
        serial: 2,
    };
    let signature: P256Signature = signing_key(17).sign(&body.signing_message());
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        body,
        scheme,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    let body = KagemushaWalletFeeScheduleBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        asset_digest: asset,
        schedule_id: 1,
        beneficiary_account_digest: beneficiary,
        basis_points: 0,
        fixed: 3,
        minimum: 3,
        maximum: 3,
        rounding: KagemushaWalletFeeRoundingV1::Down,
        signer_certificate: certificate.certificate_digest(),
    };
    let signature: P256Signature = signing_key(REGULATORY_KEY_SEED).sign(&body.signing_message());
    let schedule = KagemushaWalletFeeScheduleV1::sign(
        body,
        &certificate,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    (certificate, schedule)
}

fn scheme_policy(
    certificate: &KagemushaWalletSignerCertificateV1,
    asset: [u8; 32],
    epoch: u64,
    fee_schedule: [u8; 32],
) -> KagemushaWalletSchemePolicyV1 {
    let body = KagemushaWalletSchemePolicyBodyV1 {
        version: 1,
        scheme_id: certificate.body.scheme_id,
        asset_digest: asset,
        policy_epoch: epoch,
        enabled_controls: 0,
        fee_schedule,
        signer_certificate: certificate.certificate_digest(),
    };
    let signature: P256Signature = signing_key(REGULATORY_KEY_SEED).sign(&body.signing_message());
    KagemushaWalletSchemePolicyV1::sign(
        body,
        certificate,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap()
}

fn refresh(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    policy: &KagemushaWalletSchemePolicyV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    id: u8,
) -> Vec<u8> {
    let certificates = KagemushaWalletCertificateSetV1::new(vec![*certificate]).unwrap();
    let request = action(
        id,
        OperationActionV1::Refresh {
            kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: policy.to_canonical_bytes().unwrap(),
            certificates: norito::encode_canonical(&certificates).unwrap(),
        },
    );
    let before = wallet.snapshot().unwrap();
    let original = complete(wallet.execute(request.clone()).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&original);
    package.verify(credential).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(
        wallet.snapshot().unwrap().owned_balance,
        before.owned_balance
    );
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(wallet.execute(request).unwrap()), original);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    fold(wallet);
    assert_eq!(
        wallet.request_fee_selection().unwrap(),
        (policy.body.asset_digest, policy.body.fee_schedule)
    );
    original
}

#[test]
fn fee_fixture_signatures_bind_historical_beneficiary_and_policy_epoch() {
    let fixture = fixture();
    let scheme = &fixture.config.scheme;
    let beneficiary = kagemusha_wallet_account_digest_v1(&fixture.account).unwrap();
    let (certificate, schedule) = fee_terms(scheme, fixture.asset.asset_digest(), beneficiary);
    schedule.verify(scheme, &certificate).unwrap();
    assert_eq!(schedule.fee(97).unwrap(), 3);
    assert_eq!(schedule.body.beneficiary_account_digest, beneficiary);
    let first = scheme_policy(
        &certificate,
        fixture.asset.asset_digest(),
        1,
        schedule.fee_schedule_digest(),
    );
    let later = scheme_policy(&certificate, fixture.asset.asset_digest(), 2, [0; 32]);
    first.verify(scheme, &certificate).unwrap();
    later.verify(scheme, &certificate).unwrap();
    assert_ne!(first.scheme_policy_digest(), later.scheme_policy_digest());
    let mut changed = schedule;
    changed.body.beneficiary_account_digest = kagemusha_wallet_account_digest_v1(&AccountId::new(
        KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    ))
    .unwrap();
    assert!(changed.verify(scheme, &certificate).is_err());
    let mut changed = first;
    changed.body.policy_epoch = 2;
    assert!(changed.verify(scheme, &certificate).is_err());
}

#[test]
#[ignore = "requires exported SAME A custody, genuine full22 grant and an independently pinned finalized Load for its exact target"]
fn actual_native_fee_send_retains_historical_claim_across_restart_and_archive() {
    let output = fresh_output("KAGEMUSHA_NATIVE_FEE_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    assert_eq!(target["variant"].as_str(), Some("fee97-plus3"));
    let public = path.parent().unwrap();
    let frames_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames_a, &instruction);
    let bootstrap_a = target_original(
        public,
        &target,
        "bootstrap.norito",
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let activation_a = target_original(
        public,
        &target,
        "activation.norito",
        KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
    );
    let credential_a =
        KagemushaWalletCredentialV1::decode_canonical(&frames_a[0], &f.config.scheme.scheme_id())
            .unwrap();
    assert_eq!(
        credential_a.body.payment_key,
        public_key(&signing_key(FEE_KEY_SEED)),
        "dedicated fee incarnation; the ABC wallet cannot be relabelled"
    );
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    let count = device_a.platform.with(|state| state.sign_calls);
    assert_eq!(complete(a.bootstrap().unwrap()), bootstrap_a);
    assert_eq!(a.activation().unwrap(), activation_a);
    assert_eq!(
        device_a.platform.with(|state| state.sign_calls),
        count,
        "no recreated Bootstrap or activation"
    );
    assert_eq!(
        (
            a.snapshot().unwrap().sequence,
            a.snapshot().unwrap().owned_balance
        ),
        (0, 0)
    );

    let initial_epoch = a.epoch_progress().unwrap();
    let receipt_bytes = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_RECEIPT"),
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
    );
    let finality_bytes = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_FINALITY"),
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_FINALITY_SHA256"),
    );
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap();
    assert_eq!(receipt.scheme_id, f.config.scheme.scheme_id());
    assert_eq!(
        (
            receipt.wallet_id,
            receipt.asset_digest,
            receipt.payer_account_digest
        ),
        (
            credential_a.body.wallet_id,
            f.asset.asset_digest(),
            kagemusha_wallet_account_digest_v1(&f.account).unwrap()
        )
    );
    assert_eq!(
        (
            receipt.request_id,
            receipt.ordinal,
            receipt.amount,
            receipt.online_charge,
            receipt.charge_quote
        ),
        (LOAD_ID, 0, LOAD_AMOUNT, 0, [0; 32])
    );
    let evidence = KagemushaWalletLoadFinalityV1::decode_canonical(&finality_bytes).unwrap();
    assert_eq!(evidence.receipt_digest, receipt.receipt_digest().unwrap());
    let load = action(
        202,
        OperationActionV1::Load {
            receipt: receipt_bytes,
            finality: finality_bytes,
        },
    );
    // Load requires the exact already-executed Activate to be durably confirmed first.
    // Reuse ordinary retained signed transaction/finality ingestion, never a synthesized flag.
    let before_activation = a.snapshot().unwrap();
    let signatures = device_a.platform.with(|state| state.sign_calls);
    let (signed_activation, activation_confirmation) =
        load::confirm_existing_activation(&mut a, &sources);
    assert_eq!(a.snapshot().unwrap(), before_activation);
    assert_eq!(device_a.platform.with(|state| state.sign_calls), signatures);
    drop(a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    assert_eq!(
        a.confirm_ledger_activation(&signed_activation).unwrap(),
        activation_confirmation
    );
    assert_eq!(a.snapshot().unwrap(), before_activation);
    assert_eq!(device_a.platform.with(|state| state.sign_calls), signatures);
    let loaded = complete(a.execute(load.clone()).unwrap());
    assert_eq!(complete(a.execute(load.clone()).unwrap()), loaded);
    let mut duplicate = load;
    duplicate.request_id = [203; 32];
    assert!(
        a.execute(duplicate).is_err(),
        "one receipt cannot credit twice"
    );
    fold(&mut a);
    assert_eq!(a.snapshot().unwrap().owned_balance, LOAD_AMOUNT);
    assert_eq!(a.snapshot().unwrap().folded_balance, Some(LOAD_AMOUNT));
    assert_eq!(a.epoch_progress().unwrap(), initial_epoch);

    let f_b = sources.fixture(&setup, 1);
    let device_b = HostDevice::create(&output.join("wallet-b"), 107);
    let frames_b = device_b.enroll(&f_b);
    device_b.save_simulator();
    retain_frames(&device_b, &frames_b);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    complete(b.bootstrap().unwrap());
    fold(&mut b);
    let credential_b =
        KagemushaWalletCredentialV1::decode_canonical(&frames_b[0], &f.config.scheme.scheme_id())
            .unwrap();
    assert_ne!(credential_a.body.wallet_id, credential_b.body.wallet_id);
    let scheme = &f.config.scheme;
    let beneficiary = kagemusha_wallet_account_digest_v1(&setup.accounts[2]).unwrap();
    let (certificate, schedule) = fee_terms(scheme, f.asset.asset_digest(), beneficiary);
    let policy = scheme_policy(
        &certificate,
        f.asset.asset_digest(),
        1,
        schedule.fee_schedule_digest(),
    );
    let refresh_a = refresh(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &policy,
        &certificate,
        204,
    );
    let refresh_b = refresh(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &policy,
        &certificate,
        205,
    );
    assert_eq!(a.snapshot().unwrap().owned_balance, 100);
    assert_eq!(b.snapshot().unwrap().owned_balance, 0);

    let offer = a.offer([210; 32], 97).unwrap();
    let offer_measurement = message_census::record(
        &output,
        "fee-offer",
        KagemushaWalletMessageV1::Offer {
            offer: decode(&offer),
        },
    );
    let request_bytes = b
        .request([211; 32], &offer, Some(&(schedule, certificate)))
        .unwrap();
    let request: KagemushaWalletRequestV1 = decode(&request_bytes);
    request.verify(scheme).unwrap();
    assert_eq!((request.body.amount, request.body.fee), (97, 3));
    assert_eq!(request.body.fee_schedule, schedule.fee_schedule_digest());
    assert_eq!(request.body.policy_epoch, 1);
    assert_eq!(
        request.body.receiver_account_digest,
        kagemusha_wallet_account_digest_v1(&setup.accounts[1]).unwrap()
    );
    let request_measurement = message_census::record(
        &output,
        "fee-request",
        KagemushaWalletMessageV1::Request {
            request: request.clone(),
        },
    );
    let send = action(
        212,
        OperationActionV1::Send {
            request: request_bytes.clone(),
        },
    );
    let payment_bytes = complete(a.execute(send.clone()).unwrap());
    let payment: KagemushaWalletPaymentV1 = decode(&payment_bytes);
    let payment_measurement = message_census::record(
        &output,
        "fee-payment",
        KagemushaWalletMessageV1::Payment {
            payment: payment.clone(),
        },
    );
    let lineage_measurement = message_census::record_payment_lineage(&output, "fee", &payment);
    let certificates_a: KagemushaWalletCertificateSetV1 = decode(&frames_a[1]);
    let digests = payment
        .verify(scheme, &credential_a, &certificates_a, &request)
        .unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&payment.send, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(
        (
            payment.send.statement.next_load,
            payment.send.statement.enabled_controls
        ),
        (1, 0)
    );
    assert_eq!(a.snapshot().unwrap().owned_balance, 0);
    assert_eq!(a.snapshot().unwrap().known_burned_total, 0);
    let retained = a
        .fee_claim(digests.credit_id)
        .unwrap()
        .expect("earned fee originals");
    assert_eq!(retained.payment, payment_bytes);
    assert_eq!(retained.request, request_bytes);
    let beneficiary_original = norito::encode_canonical(&setup.accounts[2]).unwrap();
    let claim_bytes = retained
        .ledger_claim_bytes(&scheme.scheme_id(), &beneficiary_original)
        .unwrap();
    assert!(
        retained
            .ledger_claim_bytes(&scheme.scheme_id(), &frames_a[2])
            .is_err(),
        "relay cannot redirect the fee"
    );
    let claim =
        KagemushaWalletFeeClaimV1::decode_canonical(&claim_bytes, &scheme.scheme_id()).unwrap();
    assert_eq!(
        claim
            .verify(scheme, &request, &credential_a, &certificates_a)
            .unwrap()
            .fee,
        3
    );
    let signatures = device_a.platform.with(|state| state.sign_calls);
    let sent = a.snapshot().unwrap();
    drop(a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    assert_eq!(a.snapshot().unwrap(), sent);
    assert_eq!(complete(a.execute(send.clone()).unwrap()), payment_bytes);
    assert_eq!(
        a.fee_claim(digests.credit_id).unwrap(),
        Some(retained.clone())
    );
    assert_eq!(device_a.platform.with(|state| state.sign_calls), signatures);
    fold(&mut a);

    let receive = receive(&payment_bytes, &frames_a, 213);
    let received = complete(b.execute(receive.clone()).unwrap());
    assert_eq!(complete(b.execute(receive).unwrap()), received);
    let received_package: KagemushaWalletPackageV1 = decode(&received);
    received_package.verify(&credential_b).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&received_package, MemoryBudget::DEFAULT)
        .unwrap();
    fold(&mut b);
    assert_eq!(b.snapshot().unwrap().owned_balance, 97);
    assert_eq!(b.snapshot().unwrap().known_burned_total, 0);
    let acknowledgement = credited(&received);
    let credited_measurement = message_census::record(
        &output,
        "fee-credited",
        KagemushaWalletMessageV1::Credited {
            credited: decode(&acknowledgement),
        },
    );
    let (mut a, archived) =
        archive::exercise(a, &device_a, &sources, &f, &frames_a, &acknowledgement);
    assert_eq!(
        a.fee_claim(digests.credit_id).unwrap(),
        Some(retained.clone()),
        "delivery Archive must retain the unpaid earned fee"
    );
    assert_eq!(
        a.snapshot().unwrap().owned_balance
            + b.snapshot().unwrap().owned_balance
            + request.body.fee,
        LOAD_AMOUNT
    );

    // New local policy governs future requests, not the exact already signed historical fee.
    let later_policy = scheme_policy(&certificate, f.asset.asset_digest(), 2, [0; 32]);
    let later_a = refresh(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &later_policy,
        &certificate,
        214,
    );
    let later_b = refresh(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &later_policy,
        &certificate,
        215,
    );
    let b_signatures = device_b.platform.with(|state| state.sign_calls);
    assert_eq!(
        b.request([211; 32], &offer, Some(&(schedule, certificate)))
            .unwrap(),
        request_bytes
    );
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        b_signatures
    );
    let before = a.snapshot().unwrap();
    let signatures = device_a.platform.with(|state| state.sign_calls);
    drop(a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    assert_eq!(a.snapshot().unwrap(), before);
    assert_eq!(a.epoch_progress().unwrap(), initial_epoch);
    let after = a.fee_claim(digests.credit_id).unwrap().unwrap();
    assert_eq!(after, retained);
    assert_eq!(
        after
            .ledger_claim_bytes(&scheme.scheme_id(), &beneficiary_original)
            .unwrap(),
        claim_bytes
    );
    assert_eq!(device_a.platform.with(|state| state.sign_calls), signatures);
    assert_eq!(
        (
            a.snapshot().unwrap().owned_balance,
            b.snapshot().unwrap().owned_balance
        ),
        (0, 97)
    );

    let mut originals = Vec::new();
    for (name, bytes) in [
        ("request.norito", &request_bytes),
        ("payment.norito", &payment_bytes),
        ("fee-claim.norito", &claim_bytes),
    ] {
        publish(&output.join(name), bytes);
        originals.push(norito::json!({"name":name,"bytes":(bytes.len()),"sha256":(sha(bytes))}));
    }
    let mut producer_originals = Vec::new();
    for (name, bytes) in [
        ("target.json", target_bytes.clone()),
        ("offer.norito", offer),
        ("load-package.norito", loaded),
        (
            "regulatory-certificate.norito",
            norito::encode_canonical(&certificate).unwrap(),
        ),
        (
            "fee-schedule.norito",
            schedule.to_canonical_bytes().unwrap(),
        ),
        (
            "scheme-policy-1.norito",
            policy.to_canonical_bytes().unwrap(),
        ),
        (
            "scheme-policy-2.norito",
            later_policy.to_canonical_bytes().unwrap(),
        ),
        ("a-refresh-1.norito", refresh_a),
        ("b-refresh-1.norito", refresh_b),
        ("receive.norito", received),
        ("credited.norito", acknowledgement),
        ("archive-receive.norito", archived),
        ("a-refresh-2.norito", later_a),
        ("b-refresh-2.norito", later_b),
    ] {
        publish(&output.join(name), &bytes);
        producer_originals
            .push(norito::json!({"name":name,"bytes":(bytes.len()),"sha256":(sha(&bytes))}));
    }
    let complete_envelopes = vec![
        offer_measurement,
        request_measurement,
        payment_measurement,
        credited_measurement,
        lineage_measurement,
    ];
    let complete_exchange_roles =
        message_census::complete_exchange_roles(&complete_envelopes, "fee");
    let result = norito::json!({
        "schema":"iroha.kagemusha.native-fee-result.v1",
        "target_sha256":(sha(&target_bytes)),
        "receipt_sha256":(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256")),
        "finality_sha256":(env_pin("KAGEMUSHA_NATIVE_LOAD_FINALITY_SHA256")),
        "scheme_id":(hex::encode(scheme.scheme_id())),
        "manifest_digest":(hex::encode(sources.qualified.installation().1)),
        "source_pins":(source_pins()),
        "native_source_sha256":(env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "native_binary_sha256":(executable_hash()),
        "executed_ledger_setup_sha256":(setup.manifest_sha256),
        "activation_confirmation_height":(activation_confirmation.height),
        "activation_signed_transaction_sha256":(sha(&signed_activation)),
        "a_final_head":(hex::encode(before.head)),
        "a_final_sequence":(before.sequence.to_string()),
        "b_open_originals":(FRAME_NAMES.into_iter().zip(&frames_b).map(|(name,bytes)| norito::json!({"name":name,"bytes":(bytes.len()),"sha256":(sha(bytes))})).collect::<Vec<_>>()),
        "payer_wallet_id":(hex::encode(credential_a.body.wallet_id)),
        "payer_credential_digest":(hex::encode(credential_a.credential_digest())),
        "receiver_account_digest":(hex::encode(request.body.receiver_account_digest)),
        "beneficiary_account_digest":(hex::encode(beneficiary)),
        "amount":"97", "fee":"3", "gross":"100",
        "native_balances_atomic_units":["0","97"], "unpaid_fee_atomic_units":"3",
        "historical_fee_retained_after_archive_and_policy_change":true,
        "exact_restart_replay_without_new_signature":true,
        "finality_epoch":(initial_epoch.epoch),
        "scope":"Genuine installed native Send, Receive, ArchiveReceive and SchemePolicy refresh proofs over real host storage with simulated hardware and an engineering issuer. Fee claim retains its historical signed Request after restart, delivery Archive and local fee disable. No online payout or payout acknowledgement is asserted here. Four live validators, physical hardware, enabled offline controls and nonzero online charges remain separate.",
        "originals":originals, "producer_originals":producer_originals,
        "complete_envelopes":complete_envelopes,
        "complete_exchange_roles":complete_exchange_roles,
    });
    let bytes = norito::json::to_vec(&result).unwrap();
    assert!(bytes.len() <= TARGET_MAX);
    publish(&output.join("result.json"), &bytes);
    eprintln!(
        "NATIVE_FEE_RESULT path={} sha256={} ledger_payout=false",
        output.join("result.json").display(),
        sha(&bytes)
    );
}
