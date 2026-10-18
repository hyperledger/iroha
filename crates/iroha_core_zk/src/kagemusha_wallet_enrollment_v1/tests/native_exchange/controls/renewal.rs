//! Same-custody credential Refresh and Daily/Monthly rollover after the all-masks journey.
//!
//! B's 100 is received value from A's ONE genuine finalized Load, never a cloned target.
//! Fixture-issued replacement credentials are consumed by ordinary installed Refresh proofs.
//! A retained Request survives receiver renewal; the payer retires with an unresolved Payment
//! and genuinely proves its later Sends without recreating value or abandoning custody.
//! TODO: Compile and run these ReceiveRenewed/Retiring additions against matched artifacts.
//! This does not verify platform attestation or a remote credential-renewal service.
//! TODO: Execute after source handoff; native renewal restart must succeed without pre-seeding
//! provider credential records. The obsolete intake credential-N requirement is a genuine
//! regression; the separate repair authenticates the selected committed source instead.
use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::QualifiedOperationOwnerV1;
use iroha_kagemusha_proof::a_relation::schedule::compiled::OperationRoute;
use iroha_plonk_recursion::obligation::ledger::Variant;
use std::collections::BTreeSet;

#[path = "renewal/terms.rs"]
mod terms;

fn digest(value: &norito::json::Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    let bytes: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
    assert_ne!(bytes, [0; 32]);
    assert_eq!(hex::encode(bytes), text);
    bytes
}

fn inventory(value: &norito::json::Value) {
    assert_eq!(
        value["schema"].as_str(),
        Some("iroha.kagemusha.native-controls-result.v1")
    );
    let rows = value["continuation_originals"].as_array().unwrap();
    let expected = ["a", "b"]
        .into_iter()
        .flat_map(|party| FRAME_NAMES.map(|name| format!("{party}-{name}")))
        .collect::<BTreeSet<_>>();
    assert_eq!(rows.len(), expected.len());
    let names = rows
        .iter()
        .map(|row| {
            assert!(row["bytes"].as_u64().is_some_and(|length| length > 0));
            digest(&row["sha256"]);
            row["name"].as_str().unwrap().to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, expected);
    assert_eq!(value["final_owned_atomic"], norito::json!(["0", "100"]));
    assert_eq!(value["last_policy_epochs"], norito::json!([6, 1]));
}

#[allow(clippy::too_many_arguments)]
fn refresh_refused(
    wallet: &mut Wallet,
    device: &HostDevice,
    kind: KagemushaWalletPolicyUpdateKindV1,
    update: Vec<u8>,
    certificate: &KagemushaWalletSignerCertificateV1,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) {
    let certificates = norito::encode_canonical(
        &KagemushaWalletCertificateSetV1::new(vec![*certificate]).unwrap(),
    )
    .unwrap();
    records.push(original(output, &format!("{label}-update.norito"), &update));
    records.push(original(
        output,
        &format!("{label}-certificates.norito"),
        &certificates,
    ));
    let intent = action(
        next(id),
        OperationActionV1::Refresh {
            kind,
            update,
            certificates,
        },
    );
    let before = wallet.snapshot().unwrap();
    let signatures = device.platform.with(|state| state.sign_calls);
    for _ in 0..2 {
        assert!(matches!(
            wallet.execute(intent.clone()),
            Err(state::Error::Proof(
                "installed native operation preparation"
            ))
        ));
        assert_eq!(wallet.snapshot().unwrap(), before);
    }
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    records.push(norito::json!({"case":label,"refusal":"installed native operation preparation","head_unchanged":true,"payment_signatures_unchanged":true}));
}

#[allow(clippy::too_many_arguments)]
fn interval(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    request_tick: u64,
    receive_tick: u64,
    issuer: u64,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) {
    assert!(request_tick <= receive_tick && receive_tick - request_tick <= 100);
    device
        .platform
        .with(|state| state.monotonic = Ok(request_tick));
    let token = wallet.begin_direct_time_exchange().unwrap();
    let anchor = super::terms::anchor(
        certificate,
        credential.body.wallet_id,
        token.nonce(),
        issuer,
    );
    device
        .platform
        .with(|state| state.monotonic = Ok(receive_tick));
    wallet
        .finish_direct_time_exchange(token, anchor, certificate)
        .unwrap();
    refresh(
        wallet,
        device,
        sources,
        credential,
        KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
        anchor.to_canonical_bytes().unwrap(),
        certificate,
        id,
        output,
        label,
        records,
    );
    // No clock advance before the following Send: native derives this closed uncertainty
    // interval from the actual begin/finish token, not from a supplied test-only interval.
    records.push(norito::json!({"case":label,"request_tick":request_tick,"receive_tick":receive_tick,"effective_interval_at_receive":[issuer,(issuer+receive_tick-request_tick)]}));
}

#[allow(clippy::too_many_arguments)]
fn archive_current(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    ack: &[u8],
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) -> Vec<u8> {
    let before = wallet.snapshot().unwrap();
    let bytes = complete(wallet.accept_credited(ack).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&bytes);
    package.verify(credential).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, MemoryBudget::DEFAULT)
        .unwrap();
    assert!(matches!(
        package.statement.effect,
        KagemushaWalletEffectV1::ArchiveSent { .. }
    ));
    assert_eq!(
        wallet.snapshot().unwrap().owned_balance,
        before.owned_balance
    );
    assert_eq!(
        wallet.snapshot().unwrap().known_burned_total,
        before.known_burned_total
    );
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(wallet.accept_credited(ack).unwrap()), bytes);
    fold(wallet);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    records.push(original(output, &format!("{label}-archive.norito"), &bytes));
    bytes
}

#[allow(clippy::too_many_arguments)]
fn send_received_balance(
    a: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    frames: &[Vec<u8>; 4],
    request: &[u8],
    mask: u32,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) -> (OperationRequestV1, Vec<u8>) {
    let request_value: KagemushaWalletRequestV1 = decode(request);
    let before = a.snapshot().unwrap();
    let intent = action(
        next(id),
        OperationActionV1::Send {
            request: request.to_vec(),
        },
    );
    let bytes = complete(a.execute(intent.clone()).unwrap());
    let payment: KagemushaWalletPaymentV1 = decode(&bytes);
    records.push(message_census::record(
        output,
        &format!("{label}-payment"),
        KagemushaWalletMessageV1::Payment {
            payment: payment.clone(),
        },
    ));
    records.push(message_census::record_payment_lineage(
        output, label, &payment,
    ));
    let scheme = sources.installed.verifier().scheme();
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme.scheme_id()).unwrap();
    payment
        .verify(scheme, &credential, &decode(&frames[1]), &request_value)
        .unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&payment.send, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(payment.send.statement.enabled_controls, mask);
    assert_eq!(payment.send.statement.next_load, 0);
    assert_eq!(
        a.snapshot().unwrap().owned_balance + request_value.body.amount,
        before.owned_balance
    );
    assert_eq!(a.snapshot().unwrap().known_burned_total, 0);
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(a.execute(intent.clone()).unwrap()), bytes);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    fold(a);
    (intent, bytes)
}

fn assert_historical_open_refused(
    sources: &Sources,
    device: &HostDevice,
    f: &Fixture,
    frames: &[Vec<u8>; 4],
) {
    let originals =
        DirectoryOriginalsV1::open_existing(&sources.originals, PROVING_KEY_MAX_BYTES_V1).unwrap();
    let runtime = NativeWalletRuntimeV1::new(
        device.provider(f.config.scheme.scheme_id()),
        Arc::clone(&sources.installed),
        Arc::clone(&sources.qualified),
        Arc::clone(&sources.genesis),
        originals,
        ReadConfig {
            maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        },
        MemoryBudget::DEFAULT,
    );
    let failure = runtime
        .begin(&frames[0], &frames[1], &frames[2], &frames[3])
        .err()
        .expect("historical credential cannot authorize renewed source");
    let (_, error) = failure.into_parts();
    assert!(matches!(
        error,
        state::NativeOpenErrorV1::Intake(crate::kagemusha_wallet_intake_v1::Error::Authority(
            "source credential/state"
        ))
    ));
}

#[test]
fn continuation_inventory_rejects_missing_duplicate_and_foreign_originals() {
    let rows = ["a", "b"]
        .into_iter()
        .flat_map(|party| FRAME_NAMES.map(|name| format!("{party}-{name}")))
        .map(|name| norito::json!({"name":name,"bytes":1,"sha256":(hex::encode([1;32]))}))
        .collect::<Vec<_>>();
    let value = norito::json!({"schema":"iroha.kagemusha.native-controls-result.v1","continuation_originals":rows,"final_owned_atomic":["0","100"],"last_policy_epochs":[6,1]});
    inventory(&value);
    for mode in 0..3 {
        let mut changed = value.clone();
        let rows = changed
            .as_object_mut()
            .unwrap()
            .get_mut("continuation_originals")
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
    assert!(std::panic::catch_unwind(|| digest(&norito::json!("01"))).is_err());
}

#[test]
#[ignore = "requires same completed all-masks A0/B100 custody, current installed catalog and genuine original Load lineage; no credential pre-seeding"]
fn actual_native_renewal_and_daily_monthly_rollover_preserve_received_value() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CONTROLS_ROLLOVER_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f_a = permitted(sources.fixture(&setup, 0));
    let f_b = permitted(sources.fixture(&setup, 1));
    let path = selected_path("KAGEMUSHA_NATIVE_CONTROLS_RESULT");
    let bytes = read_pin(
        &path,
        1 << 20,
        &env_pin("KAGEMUSHA_NATIVE_CONTROLS_RESULT_SHA256"),
    );
    let prior: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    inventory(&prior);
    assert_eq!(prior["source_pins"], source_pins());
    assert_eq!(digest(&prior["scheme_id"]), f_a.config.scheme.scheme_id());
    assert_eq!(
        digest(&prior["manifest_digest"]),
        sources.qualified.installation().1
    );
    assert_eq!(
        prior["target_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256").as_str())
    );
    assert_eq!(
        prior["receipt_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256").as_str())
    );
    // Preserve the complete producer evidence, not a synthesized value projection.
    publish(&output.join("prior-controls-result.json"), &bytes);
    let files = norito::json!({"files":(prior["continuation_originals"].clone())});
    let root = path.parent().unwrap();
    let mut frames_a =
        FRAME_NAMES.map(|name| target_original(root, &files, &format!("a-{name}"), 32768));
    let old_frames_a = frames_a.clone();
    let mut frames_b =
        FRAME_NAMES.map(|name| target_original(root, &files, &format!("b-{name}"), 32768));
    let old_frames_b = frames_b.clone();
    let mut credential_a: KagemushaWalletCredentialV1 = decode(&frames_a[0]);
    let original_b: KagemushaWalletCredentialV1 = decode(&frames_b[0]);
    assert_eq!(
        credential_a.body.payment_key,
        public_key(&signing_key(CONTROL_A_SEED))
    );
    assert_eq!(
        original_b.body.payment_key,
        public_key(&signing_key(CONTROL_B_SEED))
    );
    assert_eq!(original_b.body.renewal_sequence, 0);
    assert_eq!(
        original_b.body.regulatory_policy,
        f_b.config.policy.regulatory_policy
    );
    let target_path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &target_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    assert_eq!(
        target["variant"].as_str(),
        Some("offline-controls-all-masks")
    );
    let public = target_path.parent().unwrap();
    let original_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    assert_eq!(frames_a, original_a);
    let instruction: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f_a, &frames_a, &instruction);
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let device_b = HostDevice::restore(&root.join("wallet-b"), &original_b);
    let mut a = sources.open(&device_a, &f_a, &frames_a);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    for (party, wallet, expected_balance) in [("a", &mut a, 0_u128), ("b", &mut b, 100_u128)] {
        let snapshot = wallet.snapshot().unwrap();
        assert_eq!(snapshot.owned_balance, expected_balance);
        assert_eq!(snapshot.known_burned_total, 0);
        assert_eq!(snapshot.folded_balance, Some(expected_balance));
        assert_eq!(
            snapshot.head,
            digest(&prior[format!("{party}_final_head").as_str()])
        );
        assert_eq!(
            snapshot.credential_digest,
            digest(&prior[format!("{party}_credential_digest").as_str()])
        );
        assert_eq!(
            snapshot.sequence,
            prior[format!("{party}_final_sequence").as_str()]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
        );
        assert_eq!(
            wallet.epoch_progress().unwrap().epoch,
            prior[format!("{party}_finality_epoch").as_str()]
                .as_u64()
                .unwrap()
        );
    }
    let epoch_a = a.epoch_progress().unwrap();
    let epoch_b = b.epoch_progress().unwrap();
    let regulator = super::terms::certificate(
        &f_b.config.scheme,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
    );
    let time_signer =
        super::terms::certificate(&f_b.config.scheme, KagemushaWalletSignerRoleV1::TimeAnchor);
    let certificates: KagemushaWalletCertificateSetV1 = decode(&frames_b[1]);
    let issuer = *certificates
        .certificate(
            &original_b.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )
        .unwrap();
    original_b.verify(&f_b.config.scheme, &issuer).unwrap();
    let mut records = Vec::new();
    let mut id = 100_u8; // Prior all-masks journey uses IDs 20..<100; Load uses202/203.
    set_policy(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        11,
        0,
        &mut id,
        &output,
        "a-receive-disabled",
        &mut records,
    );
    set_policy(
        &mut b,
        &device_b,
        &sources,
        &original_b,
        &regulator,
        12,
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1,
        &mut id,
        &output,
        "b-lease-only",
        &mut records,
    );
    interval(
        &mut b,
        &device_b,
        &sources,
        &original_b,
        &time_signer,
        1000,
        1000,
        20000,
        &mut id,
        &output,
        "expired-lease-time",
        &mut records,
    );
    let (offer30, request30, request30_setup) = request(
        &mut b,
        &mut a,
        30,
        &mut id,
        &output,
        "daily-straddle",
        &mut records,
    );
    review_refused(&mut b, &device_b, &request30, &frames_a[2]);
    execute_refused(&mut b, &device_b, &request30, &mut id);
    records.push(norito::json!({"case":"old-lease-refuses","effective_interval":[20000,20000],"lease_expires":12000,"owned_atomic":"100","head_and_signatures_unchanged":true}));
    let renewed1 = terms::renewal(&original_b, &issuer, 20000);
    let mut skipped_body = renewed1.body;
    skipped_body.renewal_sequence = 2;
    let skipped = terms::issue(skipped_body, &issuer);
    let mut foreign_body = renewed1.body;
    foreign_body.regulatory_policy.time_anchor_max_response_ms += 1;
    let foreign = terms::issue(foreign_body, &issuer);
    for (label, credential) in [
        ("skipped-renewal", skipped),
        ("changed-immutable-policy", foreign),
    ] {
        credential.verify(&f_b.config.scheme, &issuer).unwrap();
        refresh_refused(
            &mut b,
            &device_b,
            KagemushaWalletPolicyUpdateKindV1::Credential,
            credential.to_canonical_bytes().unwrap(),
            &issuer,
            &mut id,
            &output,
            label,
            &mut records,
        );
    }
    refresh(
        &mut b,
        &device_b,
        &sources,
        &renewed1,
        KagemushaWalletPolicyUpdateKindV1::Credential,
        renewed1.to_canonical_bytes().unwrap(),
        &issuer,
        &mut id,
        &output,
        "renewal-1",
        &mut records,
    );
    frames_b[0] = renewed1.to_canonical_bytes().unwrap();
    assert_eq!(
        b.snapshot().unwrap().credential_digest,
        renewed1.credential_digest()
    );
    assert_eq!(b.snapshot().unwrap().owned_balance, 100);
    b.review_send(&request30, &frames_a[2]).unwrap();
    // Fresh local request identity cannot adopt an already consumed renewal again.
    refresh_refused(
        &mut b,
        &device_b,
        KagemushaWalletPolicyUpdateKindV1::Credential,
        renewed1.to_canonical_bytes().unwrap(),
        &issuer,
        &mut id,
        &output,
        "duplicate-renewal",
        &mut records,
    );
    set_policy(
        &mut b,
        &device_b,
        &sources,
        &renewed1,
        &regulator,
        13,
        ALL,
        &mut id,
        &output,
        "b-quota-and-lease",
        &mut records,
    );
    let quota1 = terms::share(&renewed1, &regulator, 1, 20000, terms::windows(40, 50));
    refresh(
        &mut b,
        &device_b,
        &sources,
        &renewed1,
        KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        quota1.to_canonical_bytes().unwrap(),
        &regulator,
        &mut id,
        &output,
        "quota-1",
        &mut records,
    );
    interval(
        &mut b,
        &device_b,
        &sources,
        &renewed1,
        &time_signer,
        1100,
        1150,
        20950,
        &mut id,
        &output,
        "daily-straddle",
        &mut records,
    );
    let (intent30, payment30) = send_received_balance(
        &mut b,
        &device_b,
        &sources,
        &frames_b,
        &request30,
        ALL,
        &mut id,
        &output,
        "daily-straddle",
        &mut records,
    );
    let historical_b = frames_b.clone();
    assert_eq!(
        b.snapshot().unwrap().owned_balance + a.snapshot().unwrap().owned_balance + 30,
        100
    );
    let renewed2 = terms::renewal(&renewed1, &issuer, 20950);
    // Exercise genuinely selected Pending renewal, not only a released source. The
    // actual platform signer fails once AFTER Advance selected the successor capsule.
    let before_renewal = b.snapshot().unwrap();
    let update = renewed2.to_canonical_bytes().unwrap();
    let renewal_certificates =
        norito::encode_canonical(&KagemushaWalletCertificateSetV1::new(vec![issuer]).unwrap())
            .unwrap();
    records.push(original(
        &output,
        "renewal-2-with-pending-payment-update.norito",
        &update,
    ));
    records.push(original(
        &output,
        "renewal-2-with-pending-payment-certificates.norito",
        &renewal_certificates,
    ));
    let renewal_intent = action(
        next(&mut id),
        OperationActionV1::Refresh {
            kind: KagemushaWalletPolicyUpdateKindV1::Credential,
            update: update.clone(),
            certificates: renewal_certificates,
        },
    );
    let before_signatures = device_b.platform.with(|state| {
        state.sign_fault_at = Some(state.sign_calls);
        state.sign_calls
    });
    assert_eq!(
        b.execute(renewal_intent.clone()).unwrap(),
        Completion::Pending
    );
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        before_signatures + 1
    );
    drop(b); // Release the actual exclusive provider before an independent inspection.
    let mut provider = device_b.provider(f_b.config.scheme.scheme_id());
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1);
    assert!(matches!(
        provider.status(&slots[0]).unwrap(),
        KagemushaWalletSlotStatusV1::Pending(_)
    ));
    let pending = provider.current_capsule(&slots[0]).unwrap().unwrap();
    pending
        .body()
        .successor_state
        .validate_for_credential(&renewed2)
        .unwrap();
    pending
        .body()
        .statement
        .validate_for_credential(&renewed2)
        .unwrap();
    assert_eq!(
        pending.body().statement.sequence,
        before_renewal.sequence + 1
    );
    assert_eq!(provider.credential(&slots[0], 1).unwrap(), None);
    assert_eq!(provider.credential(&slots[0], 2).unwrap(), None);
    let pending_bytes = pending.to_canonical_bytes();
    records.push(original(
        &output,
        "renewal-2-selected-pending-capsule.norito",
        &pending_bytes,
    ));
    drop(provider);
    assert_historical_open_refused(&sources, &device_b, &f_b, &historical_b);
    frames_b[0] = update;
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    assert_eq!(
        b.execute(renewal_intent.clone()).unwrap(),
        Completion::Pending
    );
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        before_signatures + 1
    );
    let renewed_package_bytes = complete(
        b.resume()
            .unwrap()
            .expect("same selected renewal remains pending"),
    );
    let renewed_package: KagemushaWalletPackageV1 = decode(&renewed_package_bytes);
    renewed_package.verify(&renewed2).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&renewed_package, MemoryBudget::DEFAULT)
        .unwrap();
    assert!(matches!(
        renewed_package.statement.effect,
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
            ..
        }
    ));
    assert_eq!(b.snapshot().unwrap().sequence, before_renewal.sequence + 1);
    assert_eq!(
        b.snapshot().unwrap().owned_balance,
        before_renewal.owned_balance
    );
    assert_eq!(
        b.snapshot().unwrap().known_burned_total,
        before_renewal.known_burned_total
    );
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        before_signatures + 2
    );
    assert_eq!(
        complete(b.execute(renewal_intent).unwrap()),
        renewed_package_bytes
    );
    drop(b);
    let mut provider = device_b.provider(f_b.config.scheme.scheme_id());
    assert!(matches!(
        provider.status(&slots[0]).unwrap(),
        KagemushaWalletSlotStatusV1::Released(_)
    ));
    assert_eq!(
        provider
            .current_capsule(&slots[0])
            .unwrap()
            .unwrap()
            .to_canonical_bytes(),
        pending_bytes,
        "resume keeps exact selected proof/capsule; no reprepare"
    );
    drop(provider);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    fold(&mut b);
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        before_signatures + 2
    );
    records.push(original(
        &output,
        "renewal-2-with-pending-payment-package.norito",
        &renewed_package_bytes,
    ));
    records.push(norito::json!({"case":"pending-renewal-reopen-resume","failed_sign_attempts":1,"eventual_receipts":1,"exact_selected_capsule_preserved":true,"historical_credential_refused":true,"indexed_credential_1_and_2_absent":true}));
    assert_eq!(complete(b.execute(intent30.clone()).unwrap()), payment30);
    assert_eq!(b.snapshot().unwrap().owned_balance, 70);
    // Receive uses exactly the credential that signed the retained Payment. The payer's
    // later renewal cannot invalidate a committed credit or change its historical bytes.
    records.push(original(
        &output,
        "payment30-payer-credential.norito",
        &historical_b[0],
    ));
    records.push(original(
        &output,
        "payment30-payer-certificates.norito",
        &historical_b[1],
    ));
    // Retiring consumes the genuine folded head with 70 still owned and the committed
    // Payment30 still awaiting delivery. Its lifecycle permits the later Sends below.
    let before_retirement = b.snapshot().unwrap();
    assert_eq!(
        before_retirement.lifecycle,
        KagemushaWalletLifecycleV1::Active
    );
    assert_eq!(before_retirement.folded_balance, Some(70));
    let retirement_intent = action(next(&mut id), OperationActionV1::Retire);
    let retirement_signatures = device_b.platform.with(|state| state.sign_calls);
    let retirement_bytes = complete(b.execute(retirement_intent.clone()).unwrap());
    let retirement: KagemushaWalletPackageV1 = decode(&retirement_bytes);
    retirement.verify(&renewed2).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&retirement, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(
        retirement.statement.effect,
        KagemushaWalletEffectV1::Retiring
    );
    assert_eq!(
        retirement.statement.lifecycle,
        KagemushaWalletLifecycleV1::Retiring
    );
    assert_eq!(
        retirement.statement.predecessor.value,
        before_retirement.head
    );
    let predecessor = retirement
        .lineage
        .lineage()
        .expect("Retiring carries actual predecessor Omega");
    assert_eq!(predecessor.public.head.value, before_retirement.head);
    assert_eq!(
        predecessor.public.lifecycle,
        KagemushaWalletLifecycleV1::Active
    );
    assert_eq!(
        retirement.statement.lineage_pending_outgoing_root,
        predecessor.public.pending_outgoing_root
    );
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        retirement_signatures + 1
    );
    assert_eq!(
        complete(b.execute(retirement_intent.clone()).unwrap()),
        retirement_bytes
    );
    let retiring_route = OperationRoute {
        variant: Variant::Retiring,
        own: 10,
        incoming: None,
    };
    let QualifiedOperationOwnerV1::Consuming(retiring_owner) =
        sources.qualified.route(retiring_route).unwrap().owner()
    else {
        panic!("Retiring selects its genuine consuming prover");
    };
    let retiring_stages = retiring_owner.checkpoint_layouts().unwrap().len();
    eprintln!(
        "NATIVE_REQUIRED_ROUTE_BEGIN case=retiring route={retiring_route:?} terminal_position={retiring_stages}"
    );
    fold(&mut b);
    eprintln!("NATIVE_REQUIRED_ROUTE_END case=retiring caught_up=true");
    let retired = b.snapshot().unwrap();
    assert_eq!(retired.lifecycle, KagemushaWalletLifecycleV1::Retiring);
    assert_eq!(retired.sequence, before_retirement.sequence + 1);
    assert_eq!(retired.owned_balance, before_retirement.owned_balance);
    assert_eq!(
        retired.known_burned_total,
        before_retirement.known_burned_total
    );
    assert_eq!(retired.folded_balance, Some(70));
    drop(b);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    assert_eq!(b.snapshot().unwrap(), retired);
    assert_eq!(
        complete(b.execute(retirement_intent.clone()).unwrap()),
        retirement_bytes
    );
    assert_eq!(complete(b.execute(intent30.clone()).unwrap()), payment30);
    assert_eq!(b.snapshot().unwrap(), retired);
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        retirement_signatures + 1
    );
    records.push(original(
        &output,
        "retiring-with-outgoing-payment.norito",
        &retirement_bytes,
    ));
    // A correctly signed foreign Offer reaches the lifecycle guard. No new Request may
    // be signed, while the existing outgoing Payment and its original receipt survive.
    let offer_for_retired = a.offer([next(&mut id); 32], 1).unwrap();
    let refused_setup = [next(&mut id); 32];
    for _ in 0..2 {
        assert!(matches!(
            b.request(refused_setup, &offer_for_retired, None),
            Err(state::Error::Invalid("new Request requires active wallet"))
        ));
        assert_eq!(b.snapshot().unwrap(), retired);
    }
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        retirement_signatures + 1
    );
    records.push(original(
        &output,
        "retiring-refused-request-offer.norito",
        &offer_for_retired,
    ));
    records.push(message_census::record(
        &output,
        "retiring-refused-request-offer",
        KagemushaWalletMessageV1::Offer {
            offer: decode(&offer_for_retired),
        },
    ));

    // Renew the RECEIVER after Request30 was signed and Payment30 was irrevocably
    // committed. This exact digest inequality selects ReceiveRenewed, not ordinary
    // Receive with a renewed payer. Retain the same request and the same incarnation.
    let request30_value: KagemushaWalletRequestV1 = decode(&request30);
    assert_eq!(request30_value.receiver_credential, credential_a);
    let a_certificates: KagemushaWalletCertificateSetV1 = decode(&frames_a[1]);
    let a_issuer = *a_certificates
        .certificate(
            &credential_a.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )
        .unwrap();
    let renewed_a = terms::renewal(&credential_a, &a_issuer, 20950);
    refresh(
        &mut a,
        &device_a,
        &sources,
        &renewed_a,
        KagemushaWalletPolicyUpdateKindV1::Credential,
        renewed_a.to_canonical_bytes().unwrap(),
        &a_issuer,
        &mut id,
        &output,
        "receiver-renewal-after-request",
        &mut records,
    );
    frames_a[0] = renewed_a.to_canonical_bytes().unwrap();
    credential_a = renewed_a;
    assert_ne!(
        request30_value.receiver_credential.credential_digest(),
        credential_a.credential_digest()
    );
    assert_eq!(
        request30_value.receiver_credential.body.payment_key,
        credential_a.body.payment_key
    );
    assert_eq!(
        request30_value.receiver_credential.body.wallet_id,
        credential_a.body.wallet_id
    );
    let renewed_a_snapshot = a.snapshot().unwrap();
    let a_renewal_signatures = device_a.platform.with(|state| state.sign_calls);
    drop(a);
    assert_historical_open_refused(&sources, &device_a, &f_a, &old_frames_a);
    let mut a = sources.open(&device_a, &f_a, &frames_a);
    assert_eq!(a.snapshot().unwrap(), renewed_a_snapshot);
    assert_eq!(
        a.request(request30_setup, &offer30, None).unwrap(),
        request30
    );
    assert_eq!(
        device_a.platform.with(|state| state.sign_calls),
        a_renewal_signatures
    );
    let receive30_intent = receive(&payment30, &historical_b, id);
    let receive_renewed_route = OperationRoute {
        variant: Variant::ReceiveRenewed,
        own: 6,
        incoming: Some(5),
    };
    let incoming30: KagemushaWalletPaymentV1 = decode(&payment30);
    assert_eq!(
        incoming30
            .send
            .lineage
            .lineage()
            .unwrap()
            .public
            .enabled_controls,
        ALL
    );
    let QualifiedOperationOwnerV1::Receive(receive_owner) = sources
        .qualified
        .route(receive_renewed_route)
        .unwrap()
        .owner()
    else {
        panic!("ReceiveRenewed selects its genuine receiving prover");
    };
    let receive_stages = receive_owner.checkpoint_layouts().unwrap().len();
    eprintln!(
        "NATIVE_REQUIRED_ROUTE_BEGIN case=receive-renewed route={receive_renewed_route:?} terminal_position={receive_stages}"
    );
    let ack30 = receive_and_check(
        &mut a,
        &device_a,
        &sources,
        &historical_b,
        &credential_a,
        &request30,
        &payment30,
        &mut id,
        &output,
        "daily-straddle",
        &mut records,
    );
    eprintln!("NATIVE_REQUIRED_ROUTE_END case=receive-renewed caught_up=true");
    let credited30: KagemushaWalletCreditedV1 = decode(&ack30);
    let KagemushaWalletCreditedEvidenceV1::Receive {
        package: receive30_package,
    } = credited30.evidence
    else {
        panic!("genuine ReceiveRenewed must return its original Receive package");
    };
    assert_eq!(
        receive30_package.statement.credential_digest,
        credential_a.credential_digest()
    );
    assert_ne!(
        receive30_package.statement.credential_digest,
        request30_value.body.receiver_credential_digest
    );
    let receive30_bytes = norito::encode_canonical(&receive30_package).unwrap();
    assert_eq!(
        complete(a.execute(receive30_intent.clone()).unwrap()),
        receive30_bytes
    );
    records.push(norito::json!({"case":"receive-renewed","request_credential_digest":(hex::encode(request30_value.body.receiver_credential_digest)),"current_credential_digest":(hex::encode(credential_a.credential_digest())),"same_payment_key":true,"exact_request_after_restart":true,"folded_balance":"30"}));
    let archive30 = archive_current(
        &mut b,
        &device_b,
        &sources,
        &renewed2,
        &ack30,
        &output,
        "daily-straddle",
        &mut records,
    );
    let mut sends = vec![(intent30, payment30)];
    let mut acknowledgements = vec![(ack30, archive30)];
    let mut balances = vec![
        norito::json!({"amount":"30","interval":[20950,21000],"b":"70","a":"30","used":[30,30,0,30,0]}),
    ];
    macro_rules! refused_send {
        ($amount:expr,$label:expr) => {{
            let (_,request,_)=request(&mut b,&mut a,$amount,&mut id,&output,$label,&mut records);
            review_refused(&mut b,&device_b,&request,&frames_a[2]);
            execute_refused(&mut b,&device_b,&request,&mut id);
            records.push(norito::json!({"case":$label,"amount":($amount.to_string()),"head_and_signatures_unchanged":true}));
        }};
    }
    macro_rules! anchor {
        ($req:expr,$rcv:expr,$issuer:expr,$label:expr) => {
            interval(
                &mut b,
                &device_b,
                &sources,
                &renewed2,
                &time_signer,
                $req,
                $rcv,
                $issuer,
                &mut id,
                &output,
                $label,
                &mut records,
            )
        };
    }
    macro_rules! quota {
        ($share:expr,$label:expr) => {
            refresh(
                &mut b,
                &device_b,
                &sources,
                &renewed2,
                KagemushaWalletPolicyUpdateKindV1::QuotaShare,
                $share.to_canonical_bytes().unwrap(),
                &regulator,
                &mut id,
                &output,
                $label,
                &mut records,
            )
        };
    }
    macro_rules! pay {
        ($amount:expr,$label:expr,$a_balance:expr) => {{
            let (_, request, _) = request(
                &mut b,
                &mut a,
                $amount,
                &mut id,
                &output,
                $label,
                &mut records,
            );
            assert_eq!(
                b.snapshot().unwrap().lifecycle,
                KagemushaWalletLifecycleV1::Retiring
            );
            let (intent, payment) = send_received_balance(
                &mut b,
                &device_b,
                &sources,
                &frames_b,
                &request,
                ALL,
                &mut id,
                &output,
                $label,
                &mut records,
            );
            let retiring_send: KagemushaWalletPaymentV1 = decode(&payment);
            assert_eq!(
                retiring_send.send.statement.lifecycle,
                KagemushaWalletLifecycleV1::Retiring
            );
            assert_eq!(
                retiring_send
                    .send
                    .lineage
                    .lineage()
                    .unwrap()
                    .public
                    .lifecycle,
                KagemushaWalletLifecycleV1::Retiring
            );
            assert_eq!(
                b.snapshot().unwrap().owned_balance + a.snapshot().unwrap().owned_balance + $amount,
                100
            );
            let ack = receive_and_check(
                &mut a,
                &device_a,
                &sources,
                &frames_b,
                &credential_a,
                &request,
                &payment,
                &mut id,
                &output,
                $label,
                &mut records,
            );
            let archived = archive_current(
                &mut b,
                &device_b,
                &sources,
                &renewed2,
                &ack,
                &output,
                $label,
                &mut records,
            );
            assert_eq!(
                (
                    a.snapshot().unwrap().owned_balance,
                    b.snapshot().unwrap().owned_balance
                ),
                ($a_balance, 100 - $a_balance)
            );
            assert_eq!(
                a.snapshot().unwrap().known_burned_total + b.snapshot().unwrap().known_burned_total,
                0
            );
            sends.push((intent, payment));
            acknowledgements.push((ack, archived));
        }};
    }
    // The full debit is charged to BOTH touched Daily windows; equality at U=21000
    // touches the new window, while L=21000 stops touching the expired old window.
    refused_send!(1_u128, "daily-old-window-exhausted-after-renewal");
    anchor!(1200, 1200, 21000, "daily-boundary-exact");
    refused_send!(11_u128, "daily-new-window-preserves-straddle-usage");
    pay!(10_u128, "daily-boundary", 40_u128);
    balances.push(norito::json!({"amount":"10","interval":[21000,21000],"b":"60","a":"40","used":[30,40,0,40,0]}));
    let quota2 = terms::share(&renewed2, &regulator, 2, 20000, terms::windows(70, 50));
    quota!(quota2, "quota-2-raise-daily-without-reset");
    anchor!(1300, 1350, 21950, "monthly-straddle");
    pay!(20_u128, "monthly-straddle", 60_u128);
    balances.push(norito::json!({"amount":"20","interval":[21950,22000],"b":"40","a":"60","used":[30,60,20,60,20]}));
    refused_send!(1_u128, "monthly-old-window-exhausted");
    anchor!(1400, 1400, 22000, "monthly-boundary-exact");
    refused_send!(31_u128, "monthly-new-window-preserves-straddle-usage");
    pay!(30_u128, "monthly-boundary", 90_u128);
    balances.push(norito::json!({"amount":"30","interval":[22000,22000],"b":"10","a":"90","used":[30,60,50,60,50]}));
    let remaining = terms::windows(70, 60)
        .into_iter()
        .filter(|window| window.end_ms > 22000)
        .collect::<Vec<_>>();
    let quota3 = terms::share(&renewed2, &regulator, 3, 20000, remaining.clone());
    quota!(quota3, "quota-3-drop-expired-charged-windows");
    let mut historical = vec![terms::windows(70, 60)[0]];
    historical.extend(remaining.clone());
    let readded = terms::share(&renewed2, &regulator, 4, 20000, historical);
    refresh_refused(
        &mut b,
        &device_b,
        KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        readded.to_canonical_bytes().unwrap(),
        &regulator,
        &mut id,
        &output,
        "cannot-readd-expired-window-with-reset-usage",
        &mut records,
    );
    let mut dropped = remaining.clone();
    dropped[1].start_ms = 23000;
    dropped[1].end_ms = 24000;
    let dropped = terms::share(&renewed2, &regulator, 4, 20000, dropped);
    refresh_refused(
        &mut b,
        &device_b,
        KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        dropped.to_canonical_bytes().unwrap(),
        &regulator,
        &mut id,
        &output,
        "cannot-drop-live-charged-monthly-window",
        &mut records,
    );
    anchor!(1500, 1500, 23000, "next-period-boundary");
    let next_windows = KagemushaWalletQuotaWindowKindV1::ALL
        .into_iter()
        .map(|kind| KagemushaWalletQuotaWindowV1 {
            kind,
            start_ms: 23000,
            end_ms: 24000,
            limit: 10,
        })
        .collect();
    let quota4 = terms::share(&renewed2, &regulator, 4, 23000, next_windows);
    quota!(quota4, "quota-4-both-kinds-next-period");
    pay!(10_u128, "both-kinds-next-period", 100_u128);
    balances.push(
        norito::json!({"amount":"10","interval":[23000,23000],"b":"0","a":"100","used":[10,10]}),
    );
    let final_a = a.snapshot().unwrap();
    let final_b = b.snapshot().unwrap();
    assert_eq!((final_a.owned_balance, final_b.owned_balance), (100, 0));
    assert_eq!(
        (final_a.folded_balance, final_b.folded_balance),
        (Some(100), Some(0))
    );
    assert_eq!(final_b.credential_digest, renewed2.credential_digest());
    assert_eq!(final_b.lifecycle, KagemushaWalletLifecycleV1::Retiring);
    assert_eq!(final_a.credential_digest, credential_a.credential_digest());
    let sign_a = device_a.platform.with(|state| state.sign_calls);
    let sign_b = device_b.platform.with(|state| state.sign_calls);
    drop(a);
    drop(b);
    // Critical production boundary: no direct provider.store_credential or custody edits.
    // Successor frames must reopen from the ordinarily committed Refresh source. Initial
    // enrollment frames are historical DATA and must never authorize the renewed head.
    assert_historical_open_refused(&sources, &device_b, &f_b, &old_frames_b);
    assert_historical_open_refused(&sources, &device_a, &f_a, &old_frames_a);
    let provider = device_b.provider(f_b.config.scheme.scheme_id());
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(
        provider.credential(&slots[0], 0).unwrap(),
        Some(old_frames_b[0].clone())
    );
    assert_eq!(provider.credential(&slots[0], 1).unwrap(), None);
    assert_eq!(provider.credential(&slots[0], 2).unwrap(), None);
    drop(provider);
    let mut a = sources.open(&device_a, &f_a, &frames_a);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    assert_eq!(a.snapshot().unwrap(), final_a);
    assert_eq!(b.snapshot().unwrap(), final_b);
    assert_eq!(
        complete(b.execute(retirement_intent).unwrap()),
        retirement_bytes
    );
    assert_eq!(b.snapshot().unwrap(), final_b);
    assert_eq!(
        complete(a.execute(receive30_intent).unwrap()),
        receive30_bytes
    );
    assert_eq!(a.snapshot().unwrap(), final_a);
    assert_eq!(
        a.request(request30_setup, &offer30, None).unwrap(),
        request30
    );
    for (intent, payment) in sends {
        assert_eq!(complete(b.execute(intent).unwrap()), payment);
        assert_eq!(b.snapshot().unwrap(), final_b);
    }
    for (acknowledgement, original) in acknowledgements {
        // Exact Archive completion remains immutable even after later policy/renewal.
        let package = complete(b.accept_credited(&acknowledgement).unwrap());
        assert_eq!(package, original);
        let archived: KagemushaWalletPackageV1 = decode(&package);
        assert!(matches!(
            archived.statement.effect,
            KagemushaWalletEffectV1::ArchiveSent { .. }
        ));
        assert_eq!(b.snapshot().unwrap(), final_b);
    }
    assert_eq!(device_a.platform.with(|state| state.sign_calls), sign_a);
    assert_eq!(device_b.platform.with(|state| state.sign_calls), sign_b);
    assert_eq!(a.epoch_progress().unwrap(), epoch_a);
    assert_eq!(b.epoch_progress().unwrap(), epoch_b);
    assert_eq!(
        old_frames_b[0],
        target_original(root, &files, "b-credential.norito", 32768)
    );
    records.push(norito::json!({"case":"renewed-source-reopen","historical_credential_refused":true,"indexed_credential_1_and_2_absent":true,"successor_frames_reopen":true}));
    records.push(original(
        &output,
        "current-b-credential.norito",
        &frames_b[0],
    ));
    records.push(original(
        &output,
        "current-b-certificates.norito",
        &frames_b[1],
    ));
    records.push(original(
        &output,
        "current-a-credential.norito",
        &frames_a[0],
    ));
    records.push(original(
        &output,
        "current-a-certificates.norito",
        &frames_a[1],
    ));
    records.push(norito::json!({"case":"retiring-preserves-custody","owned_at_retirement":"70","unresolved_payment_at_retirement":"30","later_sends":4,"new_request_refused":true,"same_custody_restart_exact_retirement_retry":true,"final_lifecycle":"Retiring"}));
    let complete_exchange_roles = [
        "daily-straddle",
        "daily-boundary",
        "monthly-straddle",
        "monthly-boundary",
        "both-kinds-next-period",
    ]
    .into_iter()
    .map(|label| message_census::complete_exchange_roles(&records, label))
    .collect::<Vec<_>>();
    let result = norito::json!({
        "schema":"iroha.kagemusha.native-controls-renewal-rollover-result.v1",
        "source_pins":(source_pins()),"producer_sha256":(sha(&bytes)),
        "target_sha256":(prior["target_sha256"].clone()),"receipt_sha256":(prior["receipt_sha256"].clone()),
        "scheme_id":(hex::encode(f_a.config.scheme.scheme_id())),"manifest_digest":(hex::encode(sources.qualified.installation().1)),
        "credential_renewals":[1,2],"receiver_credential_renewals":[1],"send_mask":3,"receive_mask":0,"payer_next_load":0,
        "receive_renewed_count":1,"retiring_count":1,"retiring_send_count":4,
        "required_route_traces":[
            {"case":"retiring","variant":"Retiring","own":10,"incoming":null,"terminal_position":retiring_stages},
            {"case":"receive-renewed","variant":"ReceiveRenewed","own":6,"incoming":5,"terminal_position":receive_stages}
        ],
        "payments":5,"received_total":"100","final_owned_atomic":["100","0"],"fee_atomic":"0","burned_atomic":"0",
        "daily_monthly_expected_usage":balances,"records":records,
        "complete_exchange_roles":complete_exchange_roles,
        "same_custody_restart_exact_payment_retries":true,
        "scope":"Genuine installed native Credential Refresh, Send, Receive including ReceiveRenewed, Retiring and Archive proofs over prior one-Load lineage. Retirement preserves four subsequent Sends and exact original retries; it does not establish ledger load closure or late incoming delivery to a Retiring receiver. Fixture issuer signs replacement credentials; hardware and clock are explicit engineering fixtures. This does not qualify platform attestation, remote renewal service, physical devices, four-validator controls or release readiness."
    });
    publish(
        &output.join("rollover-result.json"),
        &norito::json::to_vec(&result).unwrap(),
    );
}
