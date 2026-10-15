//! Genuine installed-proof offline controls over one fresh Load100 and retained A/B custody.
//!
//! Every Send selector 0..=7 executes; all three controls need a credential permitting them
//! BEFORE enrollment. Signed policy changes never recreate an enrollment or refund a Send.
//! Clock/hardware/issuer are explicit engineering fixtures. Ordinary executed Load finality
//! and the complete current-source installed catalog remain mandatory external prerequisites.
//! TODO: Compile and execute this source candidate; it establishes no result until run.
use super::*;

#[path = "controls/enrollment.rs"]
mod enrollment;
#[path = "controls/renewal.rs"]
mod renewal;
#[path = "controls/target.rs"]
mod target;
#[path = "controls/terms.rs"]
mod terms;

const CONTROL_A_SEED: u8 = 113;
const CONTROL_B_SEED: u8 = 114;
const ALL: u32 = KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1;
const LEASE_EXPIRES: u64 = 12000;

fn permitted(mut f: Fixture) -> Fixture {
    f.config.policy.regulatory_policy = KagemushaWalletRegulatoryPolicyV1 {
        permitted_controls: ALL,
        blacklist_max_age_ms: 1000,
        time_anchor_max_response_ms: 100,
    };
    f.config.policy.attestation_lease_lifetime_ms = 10000;
    f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();
    f
}

fn next(id: &mut u8) -> u8 {
    let result = *id;
    *id = id.checked_add(1).unwrap();
    assert!(
        *id < 200,
        "local controls IDs cannot alias the finalized Load IDs"
    );
    result
}

fn original(output: &Path, name: &str, bytes: &[u8]) -> norito::json::Value {
    publish(&output.join(name), bytes);
    norito::json!({"name":name,"sha256":(sha(bytes)),"bytes":(bytes.len())})
}

#[allow(clippy::too_many_arguments)]
fn refresh(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    kind: KagemushaWalletPolicyUpdateKindV1,
    update: Vec<u8>,
    certificate: &KagemushaWalletSignerCertificateV1,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) {
    let certificates = KagemushaWalletCertificateSetV1::new(vec![*certificate]).unwrap();
    records.push(original(output, &format!("{label}-update.norito"), &update));
    records.push(original(
        output,
        &format!("{label}-certificates.norito"),
        &norito::encode_canonical(&certificates).unwrap(),
    ));
    let intent = action(
        next(id),
        OperationActionV1::Refresh {
            kind,
            update,
            certificates: norito::encode_canonical(&certificates).unwrap(),
        },
    );
    let before = wallet.snapshot().unwrap();
    let bytes = complete(wallet.execute(intent.clone()).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&bytes);
    package.verify(credential).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, None, MemoryBudget::DEFAULT)
        .unwrap();
    assert!(
        matches!(package.statement.effect, KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } if update_kind == kind)
    );
    assert_eq!(
        wallet.snapshot().unwrap().owned_balance,
        before.owned_balance
    );
    assert_eq!(
        wallet.snapshot().unwrap().known_burned_total,
        before.known_burned_total
    );
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(wallet.execute(intent).unwrap()), bytes);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    records.push(original(output, &format!("{label}-package.norito"), &bytes));
    fold(wallet);
}

#[allow(clippy::too_many_arguments)]
fn set_policy(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    regulator: &KagemushaWalletSignerCertificateV1,
    epoch: u64,
    mask: u32,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) {
    let policy = terms::policy(regulator, credential.body.asset_digest, epoch, mask);
    records.push(message_census::record(
        output,
        label,
        KagemushaWalletMessageV1::PolicyData {
            data: KagemushaWalletPolicyDataV1 {
                version: 1,
                scheme_id: credential.body.scheme_id,
                asset_digest: credential.body.asset_digest,
                item: KagemushaWalletPolicyDataItemV1::SchemePolicy { policy },
            },
        },
    ));
    refresh(
        wallet,
        device,
        sources,
        credential,
        KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
        policy.to_canonical_bytes().unwrap(),
        regulator,
        id,
        output,
        label,
        records,
    );
}

#[allow(clippy::too_many_arguments)]
fn set_list(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    regulator: &KagemushaWalletSignerCertificateV1,
    version: u64,
    time: u64,
    blocked: Option<[u8; 32]>,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) {
    let list = terms::blacklist(regulator, version, time, blocked);
    // Lists are standalone administrative objects, never invented peer PolicyData envelopes.
    refresh(
        wallet,
        device,
        sources,
        credential,
        KagemushaWalletPolicyUpdateKindV1::Blacklist,
        list.to_canonical_bytes().unwrap(),
        regulator,
        id,
        output,
        label,
        records,
    );
}

#[allow(clippy::too_many_arguments)]
fn set_quota(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    regulator: &KagemushaWalletSignerCertificateV1,
    share_id: u64,
    limit: u128,
    id: &mut u8,
    output: &Path,
    records: &mut Vec<norito::json::Value>,
) {
    let share = terms::quota(
        regulator,
        credential.body.asset_digest,
        credential.body.wallet_id,
        share_id,
        limit,
    );
    refresh(
        wallet,
        device,
        sources,
        credential,
        KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        share.to_canonical_bytes().unwrap(),
        regulator,
        id,
        output,
        &format!("quota-{share_id}"),
        records,
    );
}

#[allow(clippy::too_many_arguments)]
fn reanchor(
    wallet: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    credential: &KagemushaWalletCredentialV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    time: u64,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) {
    let token = wallet.begin_direct_time_exchange().unwrap();
    let anchor = terms::anchor(certificate, credential.body.wallet_id, token.nonce(), time);
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
}

fn review_refused(wallet: &mut Wallet, device: &HostDevice, request: &[u8], account: &[u8]) {
    let before = wallet.snapshot().unwrap();
    let signatures = device.platform.with(|state| state.sign_calls);
    for _ in 0..2 {
        assert!(matches!(
            wallet.review_send(request, account),
            Err(state::Error::Proof("native operation source or proof"))
        ));
        assert_eq!(wallet.snapshot().unwrap(), before);
    }
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
}

fn execute_refused(wallet: &mut Wallet, device: &HostDevice, request: &[u8], id: &mut u8) {
    let before = wallet.snapshot().unwrap();
    let signatures = device.platform.with(|state| state.sign_calls);
    let intent = action(
        next(id),
        OperationActionV1::Send {
            request: request.to_vec(),
        },
    );
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
}

#[allow(clippy::too_many_arguments)]
fn request(
    a: &mut Wallet,
    b: &mut Wallet,
    amount: u128,
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let offer = a.offer([next(id); 32], amount).unwrap();
    records.push(message_census::record(
        output,
        &format!("{label}-offer"),
        KagemushaWalletMessageV1::Offer {
            offer: decode(&offer),
        },
    ));
    let setup_id = [next(id); 32];
    let bytes = b.request(setup_id, &offer, None).unwrap();
    assert_eq!(b.request(setup_id, &offer, None).unwrap(), bytes);
    let request: KagemushaWalletRequestV1 = decode(&bytes);
    assert_eq!((request.body.amount, request.body.fee), (amount, 0));
    records.push(message_census::record(
        output,
        &format!("{label}-request"),
        KagemushaWalletMessageV1::Request { request },
    ));
    (offer, bytes, setup_id)
}

#[allow(clippy::too_many_arguments)]
fn send(
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
    let scheme = sources.installed.verifier().scheme();
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme.scheme_id()).unwrap();
    payment
        .verify(scheme, &credential, &decode(&frames[1]), &request_value)
        .unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(
            &payment.send,
            Some(&request_value.body),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    assert_eq!(payment.send.statement.enabled_controls, mask);
    assert_eq!(payment.send.statement.next_load, 1);
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

#[allow(clippy::too_many_arguments)]
fn receive_and_check(
    b: &mut Wallet,
    device: &HostDevice,
    sources: &Sources,
    frames_a: &[Vec<u8>; 4],
    credential_b: &KagemushaWalletCredentialV1,
    request: &[u8],
    payment: &[u8],
    id: &mut u8,
    output: &Path,
    label: &str,
    records: &mut Vec<norito::json::Value>,
) -> Vec<u8> {
    let request: KagemushaWalletRequestV1 = decode(request);
    let before = b.snapshot().unwrap();
    let intent = receive(payment, frames_a, next(id));
    let bytes = complete(b.execute(intent.clone()).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&bytes);
    package.verify(credential_b).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, Some(&request.body), MemoryBudget::DEFAULT)
        .unwrap();
    let acknowledgement = credited(&bytes);
    records.push(message_census::record(
        output,
        &format!("{label}-credited"),
        KagemushaWalletMessageV1::Credited {
            credited: decode(&acknowledgement),
        },
    ));
    assert_eq!(
        b.snapshot().unwrap().owned_balance,
        before.owned_balance + request.body.amount
    );
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(b.execute(intent).unwrap()), bytes);
    // Permanent credit identity, even when the foreign lifecycle request identity changes.
    let consumed = b.snapshot().unwrap();
    assert!(b.execute(receive(payment, frames_a, next(id))).is_err());
    assert_eq!(b.snapshot().unwrap(), consumed);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    fold(b);
    assert_eq!(b.snapshot().unwrap().known_burned_total, 0);
    acknowledgement
}

#[test]
#[ignore = "requires fresh permitted target SAME A custody, genuine complete52 catalog and independently executed pinned Activate/Load"]
fn actual_native_all_control_masks_preserve_committed_payment_and_conservation() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CONTROLS_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = permitted(sources.fixture(&setup, 0));
    let path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    assert_eq!(
        target["variant"].as_str(),
        Some("offline-controls-all-masks")
    );
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
        public_key(&signing_key(CONTROL_A_SEED)),
        "dedicated controls incarnation; the ABC wallet cannot be relabelled"
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

    assert_eq!(
        credential_a.body.regulatory_policy,
        f.config.policy.regulatory_policy
    );
    assert_eq!(credential_a.body.regulatory_policy.permitted_controls, ALL);
    assert_eq!(credential_a.body.lease_expires_at_ms, LEASE_EXPIRES);
    let f_b = permitted(sources.fixture(&setup, 1));
    let device_b = HostDevice::create(&output.join("wallet-b"), CONTROL_B_SEED);
    let frames_b = enrollment::enroll(&device_b, &f_b);
    device_b.save_simulator();
    retain_frames(&device_b, &frames_b);
    let credential_b =
        KagemushaWalletCredentialV1::decode_canonical(&frames_b[0], &f.config.scheme.scheme_id())
            .unwrap();
    assert_eq!(
        credential_b.body.regulatory_policy,
        f_b.config.policy.regulatory_policy
    );
    assert_eq!(credential_b.body.lease_expires_at_ms, LEASE_EXPIRES);
    assert_ne!(credential_a.body.wallet_id, credential_b.body.wallet_id);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    complete(b.bootstrap().unwrap());
    fold(&mut b);
    let regulator = terms::certificate(
        &f.config.scheme,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
    );
    let time_signer = terms::certificate(&f.config.scheme, KagemushaWalletSignerRoleV1::TimeAnchor);
    let mut id = 20;
    let mut records = Vec::new();
    let mut masks = Vec::new();
    let mut completed_sends = Vec::new();
    let a_account = credential_a.body.account_digest;
    let b_account = credential_b.body.account_digest;
    set_policy(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        1,
        ALL,
        &mut id,
        &output,
        "a-policy-1",
        &mut records,
    );
    set_policy(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &regulator,
        1,
        ALL,
        &mut id,
        &output,
        "b-policy-1",
        &mut records,
    );
    set_list(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        1,
        3000,
        None,
        &mut id,
        &output,
        "a-list-1",
        &mut records,
    );
    set_list(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &regulator,
        1,
        3000,
        None,
        &mut id,
        &output,
        "b-list-1",
        &mut records,
    );
    set_quota(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        1,
        40,
        &mut id,
        &output,
        &mut records,
    );
    reanchor(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &time_signer,
        3000,
        &mut id,
        &output,
        "anchor-1",
        &mut records,
    );
    let (offer40, request40, setup40) =
        request(&mut a, &mut b, 40, &mut id, &output, "mask-7", &mut records);
    assert_eq!(
        decode::<KagemushaWalletRequestV1>(&request40)
            .body
            .receiver_blacklist_version,
        1
    );
    a.review_send(&request40, &frames_b[2]).unwrap();
    let (send40, payment40) = send(
        &mut a,
        &device_a,
        &sources,
        &frames_a,
        &request40,
        7,
        &mut id,
        &output,
        "mask-7",
        &mut records,
    );
    masks.push(7_u32);
    completed_sends.push((send40.clone(), payment40.clone()));
    assert_eq!(
        a.snapshot().unwrap().owned_balance + b.snapshot().unwrap().owned_balance + 40,
        100
    );

    // The next Request must be issued AFTER the first Send, so it binds ordinal1.
    let (_, request7, _) = request(&mut a, &mut b, 7, &mut id, &output, "mask-0", &mut records);
    assert_eq!(
        decode::<KagemushaWalletRequestV1>(&request7)
            .body
            .send_ordinal,
        1
    );
    set_list(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &regulator,
        2,
        3000,
        Some(a_account),
        &mut id,
        &output,
        "b-list-2-blocks-a",
        &mut records,
    );
    let blocked_offer = a.offer([next(&mut id); 32], 7).unwrap();
    records.push(message_census::record(
        &output,
        "blocked-new-request-offer",
        KagemushaWalletMessageV1::Offer {
            offer: decode(&blocked_offer),
        },
    ));
    let before = b.snapshot().unwrap();
    let signatures = device_b.platform.with(|state| state.sign_calls);
    assert!(matches!(
        b.request([next(&mut id); 32], &blocked_offer, None),
        Err(state::Error::Invalid("G1 validation"))
    ));
    assert_eq!(b.snapshot().unwrap(), before);
    assert_eq!(device_b.platform.with(|state| state.sign_calls), signatures);
    assert_eq!(b.request(setup40, &offer40, None).unwrap(), request40);
    assert_eq!(b.snapshot().unwrap(), before);
    assert_eq!(device_b.platform.with(|state| state.sign_calls), signatures);
    // Receiver policy changed after irreversible Send. Receive proves the Request's
    // retained version1 gap through current history; it must not consult the blocking v2.
    let ack = receive_and_check(
        &mut b,
        &device_b,
        &sources,
        &frames_a,
        &credential_b,
        &request40,
        &payment40,
        &mut id,
        &output,
        "mask-7",
        &mut records,
    );
    let (reopened, archived) = archive::exercise(a, &device_a, &sources, &f, &frames_a, &ack);
    a = reopened;
    records.push(original(&output, "mask-7-archive.norito", &archived));
    assert_eq!(
        a.snapshot().unwrap().owned_balance + b.snapshot().unwrap().owned_balance,
        100
    );

    review_refused(&mut a, &device_a, &request7, &frames_b[2]);
    execute_refused(&mut a, &device_a, &request7, &mut id);
    // Raising the limit to46 must NOT reset the40 already consumed. A fresh7 still fails.
    set_quota(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        2,
        46,
        &mut id,
        &output,
        &mut records,
    );
    review_refused(&mut a, &device_a, &request7, &frames_b[2]);
    execute_refused(&mut a, &device_a, &request7, &mut id);
    set_quota(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        3,
        100,
        &mut id,
        &output,
        &mut records,
    );
    a.review_send(&request7, &frames_b[2]).unwrap();
    set_list(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        2,
        3000,
        Some(b_account),
        &mut id,
        &output,
        "a-list-2-blocks-b",
        &mut records,
    );
    review_refused(&mut a, &device_a, &request7, &frames_b[2]);
    execute_refused(&mut a, &device_a, &request7, &mut id);
    set_list(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        3,
        3000,
        None,
        &mut id,
        &output,
        "a-list-3",
        &mut records,
    );
    a.review_send(&request7, &frames_b[2]).unwrap();
    set_list(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &regulator,
        3,
        3000,
        None,
        &mut id,
        &output,
        "b-list-3",
        &mut records,
    );

    // One funded incarnation covers every current Send mask, with genuine Receive
    // selector1 (recorded blacklist history) and ArchiveReceive for each Payment.
    for mask in 0_u32..=6 {
        let label = format!("mask-{mask}");
        set_policy(
            &mut a,
            &device_a,
            &sources,
            &credential_a,
            &regulator,
            u64::from(mask) + 2,
            mask,
            &mut id,
            &output,
            &format!("a-policy-{}", mask + 2),
            &mut records,
        );
        let request = if mask == 0 {
            request7.clone()
        } else {
            request(&mut a, &mut b, 7, &mut id, &output, &label, &mut records).1
        };
        a.review_send(&request, &frames_b[2]).unwrap();
        let (intent, payment) = send(
            &mut a,
            &device_a,
            &sources,
            &frames_a,
            &request,
            mask,
            &mut id,
            &output,
            &label,
            &mut records,
        );
        let ack = receive_and_check(
            &mut b,
            &device_b,
            &sources,
            &frames_a,
            &credential_b,
            &request,
            &payment,
            &mut id,
            &output,
            &label,
            &mut records,
        );
        let (reopened, archived) = archive::exercise(a, &device_a, &sources, &f, &frames_a, &ack);
        a = reopened;
        records.push(original(
            &output,
            &format!("{label}-archive.norito"),
            &archived,
        ));
        completed_sends.push((intent, payment));
        masks.push(mask);
        assert_eq!(
            a.snapshot().unwrap().owned_balance + b.snapshot().unwrap().owned_balance,
            100
        );
    }
    assert_eq!(a.snapshot().unwrap().owned_balance, 11);
    assert_eq!(b.snapshot().unwrap().owned_balance, 89);
    set_policy(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        9,
        ALL,
        &mut id,
        &output,
        "a-policy-9",
        &mut records,
    );
    let (_, request11, _) = request(
        &mut a,
        &mut b,
        11,
        &mut id,
        &output,
        "after-expiry",
        &mut records,
    );
    a.review_send(&request11, &frames_b[2]).unwrap();

    // Same signed anchor, forward-only simulated monotonic clock: U is exactly the
    // lease deadline. Refresh the list so expiry is the only failing active condition.
    device_a.platform.with(|state| state.monotonic = Ok(10000));
    set_list(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        4,
        LEASE_EXPIRES,
        None,
        &mut id,
        &output,
        "a-list-4",
        &mut records,
    );
    review_refused(&mut a, &device_a, &request11, &frames_b[2]);
    execute_refused(&mut a, &device_a, &request11, &mut id);
    assert_eq!(complete(a.execute(send40.clone()).unwrap()), payment40);
    // A signed later scheme policy disables lease enforcement, leaving the list and
    // quota active. This is not renewal: the original credential remains unchanged.
    set_policy(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        10,
        3,
        &mut id,
        &output,
        "a-policy-10",
        &mut records,
    );
    a.review_send(&request11, &frames_b[2]).unwrap();
    device_a.platform.with(|state| state.monotonic = Ok(11001));
    review_refused(&mut a, &device_a, &request11, &frames_b[2]);
    execute_refused(&mut a, &device_a, &request11, &mut id);
    set_list(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &regulator,
        5,
        13001,
        None,
        &mut id,
        &output,
        "a-list-5",
        &mut records,
    );
    a.review_send(&request11, &frames_b[2]).unwrap();
    device_a.platform.with(|state| state.boot = Ok([0xbc; 32]));
    review_refused(&mut a, &device_a, &request11, &frames_b[2]);
    execute_refused(&mut a, &device_a, &request11, &mut id);
    assert_eq!(complete(a.execute(send40).unwrap()), payment40);
    reanchor(
        &mut a,
        &device_a,
        &sources,
        &credential_a,
        &time_signer,
        13001,
        &mut id,
        &output,
        "anchor-after-boot",
        &mut records,
    );
    a.review_send(&request11, &frames_b[2]).unwrap();
    let (intent, payment) = send(
        &mut a,
        &device_a,
        &sources,
        &frames_a,
        &request11,
        3,
        &mut id,
        &output,
        "after-expiry",
        &mut records,
    );
    set_list(
        &mut b,
        &device_b,
        &sources,
        &credential_b,
        &regulator,
        4,
        13001,
        Some(a_account),
        &mut id,
        &output,
        "b-list-4-blocks-a",
        &mut records,
    );
    let ack = receive_and_check(
        &mut b,
        &device_b,
        &sources,
        &frames_a,
        &credential_b,
        &request11,
        &payment,
        &mut id,
        &output,
        "after-expiry",
        &mut records,
    );
    let (reopened, archived) = archive::exercise(a, &device_a, &sources, &f, &frames_a, &ack);
    a = reopened;
    records.push(original(&output, "after-expiry-archive.norito", &archived));
    completed_sends.push((intent, payment));
    let final_a = a.snapshot().unwrap();
    let final_b = b.snapshot().unwrap();
    assert_eq!((final_a.owned_balance, final_b.owned_balance), (0, 100));
    assert_eq!(
        (final_a.known_burned_total, final_b.known_burned_total),
        (0, 0)
    );
    assert_eq!(
        (final_a.folded_balance, final_b.folded_balance),
        (Some(0), Some(100))
    );
    let signatures = device_a.platform.with(|state| state.sign_calls);
    drop(a);
    drop(b);
    let mut a = sources.open(&device_a, &f, &frames_a);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    assert_eq!(a.snapshot().unwrap(), final_a);
    assert_eq!(b.snapshot().unwrap(), final_b);
    let b_signatures = device_b.platform.with(|state| state.sign_calls);
    assert_eq!(b.request(setup40, &offer40, None).unwrap(), request40);
    assert_eq!(b.snapshot().unwrap(), final_b);
    assert_eq!(
        device_b.platform.with(|state| state.sign_calls),
        b_signatures
    );
    for (intent, original) in completed_sends {
        assert_eq!(complete(a.execute(intent).unwrap()), original);
        assert_eq!(a.snapshot().unwrap(), final_a);
    }
    assert_eq!(device_a.platform.with(|state| state.sign_calls), signatures);
    assert_eq!(a.epoch_progress().unwrap(), initial_epoch);
    masks.sort();
    assert_eq!(masks, (0_u32..=7).collect::<Vec<_>>());
    // Public originals and exact terminal source identity bind the optional renewal
    // continuation to these SAME two persisted incarnations; they grant no new balance.
    let continuation_originals = [("a", &frames_a), ("b", &frames_b)]
        .into_iter()
        .flat_map(|(party, frames)| {
            FRAME_NAMES
                .into_iter()
                .zip(frames)
                .map(move |(name, bytes)| (format!("{party}-{name}"), bytes))
        })
        .map(|(name, bytes)| original(&output, &name, bytes))
        .collect::<Vec<_>>();
    let result = norito::json!({
        "schema":"iroha.kagemusha.native-controls-result.v1",
        "continuation_originals":continuation_originals,
        "a_final_head":(hex::encode(final_a.head)),"b_final_head":(hex::encode(final_b.head)),
        "a_final_sequence":(final_a.sequence.to_string()),"b_final_sequence":(final_b.sequence.to_string()),
        "a_credential_digest":(hex::encode(final_a.credential_digest)),"b_credential_digest":(hex::encode(final_b.credential_digest)),
        "a_finality_epoch":(a.epoch_progress().unwrap().epoch),"b_finality_epoch":(b.epoch_progress().unwrap().epoch),
        "last_policy_epochs":[10,1],
        "source_pins":(source_pins()),"target_sha256":(sha(&target_bytes)),
        "receipt_sha256":(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256")),
        "scheme_id":(hex::encode(f.config.scheme.scheme_id())),
        "manifest_digest":(hex::encode(sources.qualified.installation().1)),
        "executed_send_masks":masks,"payments":9,"received_total":"100",
        "final_owned_atomic":["0","100"],"burned_atomic":"0","fee_atomic":"0",
        "daily_monthly_usage_preserved_on_share_refresh":true,
        "recorded_blacklist_receive_after_later_block":true,
        "fresh_refusals_preserve_head_and_payment_signatures":true,
        "same_custody_restart_exact_payment_retries":true,
        "records":records,
        "scope":"Actual installed native proofs over one ordinary finalized Load and all eight Send masks, Receive with retained blacklist history, ArchiveReceive and exact replay. Signed policy/issuer and simulated monotonic/hardware inputs are explicit engineering fixtures. No four-validator run, credential renewal, quota-boundary rollover, physical-device or release qualification."
    });
    publish(
        &output.join("controls-result.json"),
        &norito::json::to_vec(&result).unwrap(),
    );
}
