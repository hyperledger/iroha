//! Exact DATA projection and durable lookup tests; relation authority is explicitly mocked.
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, bootstrap, fixture, frozen, wallet};

fn originals(claim: &KagemushaWalletUnloadClaimV1) -> Option<ChargeOriginalsV1> {
    claim.charge.quote().map(|quote| ChargeOriginalsV1 {
        quote: quote.to_canonical_bytes().unwrap(),
        certificates: archive::encode(
            &KagemushaWalletCertificateSetV1::new(vec![
                *claim
                    .certificates
                    .certificate(
                        &quote.body.signer_certificate,
                        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
                    )
                    .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap(),
    })
}
#[test]
fn canonical_projection_keeps_exact_package_and_rejects_foreign_account_quote_and_beneficiary() {
    let scheme = fixture("KagemushaWalletSchemeV1");
    let claim: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    let amount = claim.payout().unwrap().amount;
    let charge = originals(&claim);
    let beneficiary = archive::encode(claim.charge.beneficiary().unwrap()).unwrap();
    let run =
        |charge: Option<&ChargeOriginalsV1>, account: &AccountId, beneficiary: Option<&[u8]>| {
            compose(
                &scheme,
                amount,
                charge,
                claim.credential,
                claim.certificates.clone(),
                claim.package.clone(),
                account,
                beneficiary,
            )
        };
    assert_eq!(
        run(charge.as_ref(), &claim.account, Some(&beneficiary)).unwrap(),
        claim.to_canonical_bytes().unwrap()
    );
    assert!(run(charge.as_ref(), &claim.account, None).is_err());
    assert!(run(None, &claim.account, Some(&beneficiary)).is_err());
    assert!(run(None, &claim.account, None).is_err());
    let wrong_account = claim.charge.beneficiary().unwrap();
    assert_ne!(wrong_account, &claim.account);
    assert!(run(charge.as_ref(), wrong_account, Some(&beneficiary)).is_err());
    assert!(
        run(
            charge.as_ref(),
            &claim.account,
            Some(&archive::encode(&claim.account).unwrap())
        )
        .is_err()
    );
    let mut trailing = beneficiary.clone();
    trailing.push(0);
    assert!(run(charge.as_ref(), &claim.account, Some(&trailing)).is_err());
    let mut altered = charge.unwrap();
    altered.quote[50] ^= 1;
    assert!(run(Some(&altered), &claim.account, Some(&beneficiary)).is_err());
}

fn prepared() -> (Wallet, OperationRequestV1, AccountId, [u8; 32], [u8; 32]) {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    w.scheduler().set_activity(true, false);
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let (_, manifest) = w.sync_manifest().unwrap();
    let step = w.indexed_step(&manifest, 0).unwrap();
    let source = w.source_custody(&manifest, &step).unwrap();
    let lineage = w.read_fold(&step).unwrap().unwrap().record.lineage;
    let mut next = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&w.scheme_id, &w.wallet_id, 0),
            redeem_ordinal: 0,
            amount: 10,
            online_charge: 0,
            charge_quote: [0; 32],
        },
    );
    let c = &mut next.capsule;
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage.clone(),
    };
    c.statement.lineage_burned_total = lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    let capsule = c.capsule_digest().unwrap();
    w.retain_source_custody(capsule, &source).unwrap();
    w.commit(next.clone()).unwrap();
    let (root, mut manifest) = w.sync_manifest().unwrap();
    let request = OperationRequestV1 {
        request_id: [101; 32],
        action: OperationActionV1::Unload {
            amount: 10,
            charge: None,
        },
    };
    let intent = NativeIntentV1::user(request.clone());
    let original = archive::encode(&intent).unwrap();
    let request_object = w
        .archive
        .write_object(&original, REQUEST_MAX_BYTES)
        .unwrap();
    let plan = Plan {
        version: 1,
        scheme: w.scheme_id,
        wallet: w.wallet_id,
        request_id: request.request_id,
        kind: KagemushaWalletOperationKindV1::Unload,
        request: digest("wallet-preparation-request", &original),
        source: boot.capsule.capsule_digest().unwrap(),
        native: vec![1],
        request_object,
        draft: source,
    };
    let address = w
        .archive
        .write_object(&archive::encode(&plan).unwrap(), PLAN_BOUND)
        .unwrap();
    let entry = Entry {
        request: request_object,
        plan: Some(address),
        capsule: Some(capsule),
        operation: Some(next.capsule.operation_id),
    };
    manifest.preparations = manifest
        .preparations
        .set(
            &mut w.archive,
            request.request_id,
            &archive::encode(&entry).unwrap(),
        )
        .unwrap();
    manifest.capsule_plans = manifest
        .capsule_plans
        .set(&mut w.archive, capsule, &address)
        .unwrap();
    w.publish_manifest(root, &manifest).unwrap();
    let account = fixture::<KagemushaWalletUnloadClaimV1>("KagemushaWalletUnloadClaimV1").account;
    assert_eq!(
        kagemusha_wallet_account_digest_v1(&account).unwrap(),
        next.credential.body.account_digest
    );
    let credential = w
        .archive
        .write_object(
            &next.credential.to_canonical_bytes().unwrap(),
            KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        )
        .unwrap();
    (w, request, account, capsule, credential)
}

#[test]
fn permanent_plan_projects_after_capsule_collection_and_restart_without_signing() {
    let (mut w, request, account, capsule, _) = prepared();
    let original = w
        .retained_unload_claim(&request.request_id, &account, None)
        .unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let (_, manifest) = w.sync_manifest().unwrap();
    let previous = w
        .indexed_step(&manifest, manifest.indexed.unwrap())
        .unwrap();
    let source = w.source_custody(&manifest, &previous).unwrap();
    let lineage = w.read_fold(&previous).unwrap().unwrap().record.lineage;
    let mut next = frozen(Some(&previous.frozen), KagemushaWalletEffectV1::Retiring);
    let c = &mut next.capsule;
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage.clone(),
    };
    c.statement.lineage_burned_total = lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    w.retain_source_custody(c.capsule_digest().unwrap(), &source)
        .unwrap();
    w.commit(next).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    while !matches!(
        w.collect_retained_step(1).unwrap(),
        CollectionStatus::Collected(1)
    ) {}
    assert!(
        w.archive
            .get(ArchiveKey::Capsule(capsule), FROZEN_BOUND)
            .unwrap()
            .is_none()
    );
    let signatures = w.custody.signatures;
    let mut w = Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id).unwrap();
    assert_eq!(
        w.retained_unload_claim(&request.request_id, &account, None)
            .unwrap(),
        original
    );
    assert_eq!(w.custody.signatures, signatures);
    let claim = KagemushaWalletUnloadClaimV1::decode_canonical(&original, &w.scheme_id).unwrap();
    assert_eq!(claim.payout().unwrap().account_payout, 10);
}

#[test]
fn unknown_and_lost_selected_originals_never_reconstruct_a_claim() {
    let (mut w, request, account, _, credential) = prepared();
    assert!(w.retained_unload_claim(&[0; 32], &account, None).is_err());
    assert!(w.retained_unload_claim(&[102; 32], &account, None).is_err());
    assert!(
        w.retained_unload_claim(&request.request_id, &account, Some(&[]))
            .is_err()
    );
    assert!(
        w.retained_unload_claim(
            &request.request_id,
            &account,
            Some(&vec![0; KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1 + 1])
        )
        .is_err()
    );
    w.archive.remove(ArchiveKey::Object(credential)).unwrap();
    assert!(matches!(
        w.retained_unload_claim(&request.request_id, &account, None),
        Err(Error::WitnessLost(_))
    ));
}
