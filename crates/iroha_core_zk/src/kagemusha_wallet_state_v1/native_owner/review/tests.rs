//! Engineering original/binding tests. These never install an owner or qualify a fold/phone.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};

fn account_original(seed: u8, algorithm: Algorithm) -> (AccountId, Vec<u8>) {
    let key = KeyPair::from_seed(vec![seed; 32], algorithm);
    let account = AccountId::new(key.public_key().clone());
    let original = norito::encode_canonical(&account).unwrap();
    (account, original)
}

fn receiver_original() -> Vec<u8> {
    // Public fixed DATA seed owned by Model vectors_tests::RECEIVER_SEED, not a wallet key.
    let (account, original) = account_original(0x52, Algorithm::Ed25519);
    assert_eq!(
        kagemusha_wallet_account_digest_v1(&account).unwrap(),
        request().body.receiver_account_digest
    );
    original
}

fn vectors() -> norito::json::Value {
    norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap()
}
fn request() -> KagemushaWalletRequestV1 {
    let all = vectors();
    let row = all["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"].as_str() == Some("Request"))
        .unwrap();
    let envelope: KagemushaWalletEnvelopeV1 =
        archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
    let KagemushaWalletMessageV1::Request { request } = envelope.message else {
        panic!("Request fixture");
    };
    request
}
fn scheme() -> KagemushaWalletSchemeV1 {
    super::super::super::tests::fixture("KagemushaWalletSchemeV1")
}
fn credential() -> KagemushaWalletCredentialV1 {
    super::super::super::tests::fixture("KagemushaWalletCredentialV1")
}
fn unadmitted_review_fixture() -> ReviewedOperationV1 {
    let request = request();
    request.verify(&scheme()).unwrap();
    let owner = credential();
    let head = KagemushaWalletStateCommitmentV1 {
        value: kagemusha_wallet_field_from_u128_v1(1),
    };
    ReviewedOperationV1 {
        unload_beneficiary: None,
        projection: NativeOperationReviewV1 {
            kind: KagemushaWalletOperationKindV1::Send,
            amount: request.body.amount,
            fee: request.body.fee,
            gross_debit: request.body.amount.checked_add(request.body.fee).unwrap(),
            net_destination_amount: request.body.amount,
            receiver_wallet_id: Some(request.body.receiver_wallet_id),
            destination_account_digest: request.body.receiver_account_digest,
            destination_account_original: Some(receiver_original()),
            request_digest: request.request_digest(),
            charge_quote_digest: [0; 32],
            scheme_id: request.body.scheme_id,
            wallet_id: request.body.payer_wallet_id,
            current_head: head.value,
            source_state_commitment: head.value,
            source_capsule_digest: [2; 32],
            credential_digest: owner.credential_digest(),
            payment_key: owner.body.payment_key,
            artifact_manifest_digest: [3; 32],
        },
        source: ReviewSourceV1 {
            marker: KagemushaWalletMarkerV1 {
                version: 1,
                scheme_id: request.body.scheme_id,
                asset_digest: request.body.asset_digest,
                wallet_id: request.body.payer_wallet_id,
                payment_key: owner.body.payment_key,
                generation: 5,
                state: KagemushaWalletMarkerStateV1::Head {
                    sequence: 0,
                    operation_id: [4; 32],
                    head,
                    capsule_digest: [2; 32],
                    predecessor_capsule_digest: [0; 32],
                },
            },
            completion: [5; 32],
            archive_checkpoint: [6; 32],
            artifact_manifest: [3; 32],
            selected_generation: 4,
        },
        action: OperationActionV1::Send {
            request: KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Request { request })
                .to_canonical_bytes()
                .unwrap(),
        },
    }
}

#[test]
fn signed_request_cannot_display_a_false_fee_or_retargeted_destination() {
    let original = request();
    let scheme = scheme();
    original.verify(&scheme).unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.body.fee = changed.body.fee.checked_add(1).unwrap(),
            1 => changed.body.amount = changed.body.amount.checked_add(1).unwrap(),
            2 => changed.body.receiver_wallet_id[0] ^= 1,
            3 => changed.body.receiver_account_digest[0] ^= 1,
            _ => changed.body.payer_wallet_id[0] ^= 1,
        }
        assert!(changed.verify(&scheme).is_err());
    }
}

#[test]
fn whole_send_check_rejects_ordinal_and_spendable_changes_even_with_a_valid_signature() {
    let request = request();
    let scheme = scheme();
    request.verify(&scheme).unwrap();
    let owner = credential();
    let usage = KagemushaWalletQuotaUsageArrayV1::empty();
    let mut state =
        KagemushaWalletStateV1::bootstrap(&owner, kagemusha_wallet_field_from_u128_v1(17)).unwrap();
    state.core.enabled_controls = 0;
    state.core.balance = request.body.amount.checked_add(request.body.fee).unwrap();
    state.core.next_send = request.body.send_ordinal;
    state.core.policy_epoch = request.body.policy_epoch;
    state.core.accepted_time_floor_ms = request.body.receiver_accepted_time_ms;
    state.rest.scheme_policy = request.body.scheme_policy;
    state.rest.fee_schedule = request.body.fee_schedule;
    let omega = |state: &KagemushaWalletStateV1| KagemushaWalletLineagePublicV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        relation_id: scheme.relation_id,
        head: state.commitment().unwrap(),
        wallet_id: owner.body.wallet_id,
        credential_digest: owner.credential_digest(),
        payment_key: owner.body.payment_key,
        lifecycle: state.core.lifecycle,
        policy_epoch: state.core.policy_epoch,
        enabled_controls: state.core.enabled_controls,
        burned_total: 0,
        pending_outgoing_root: state.core.pending_outgoing_root,
        credit_digest_root: kagemusha_wallet_field_from_u128_v1(1),
    };
    let check = |state: &KagemushaWalletStateV1| {
        request.check_send(&KagemushaWalletSendInputsV1 {
            payer_credential: &owner,
            payer_state: state,
            omega: &omega(state),
            anchored: None,
            now: None,
            blacklist: None,
            quota_share: None,
            quota_usage: &usage,
        })
    };
    check(&state).unwrap(); // Pure Model projection, never an admitted/proven Native fold.
    let mut next = state;
    next.core.next_send += 1;
    assert!(check(&next).is_err());
    let mut low = state;
    low.core.balance -= 1;
    assert!(check(&low).is_err());
}

#[test]
fn hardware_ui_data_and_copied_originals_cannot_replace_retained_action() {
    let review = unadmitted_review_fixture();
    let original = review.send_original().unwrap().to_vec();
    let mut data = review.projection().clone();
    data.fee = 0;
    data.gross_debit = 1;
    data.receiver_wallet_id = Some([99; 32]);
    data.destination_account_original.as_mut().unwrap()[0] ^= 1;
    let mut copied = original.clone();
    copied[0] ^= 1;
    assert_ne!(data, *review.projection());
    assert_ne!(copied, review.send_original().unwrap());
    let request = review.into_request([7; 32]).unwrap();
    assert_eq!(request.request_id, [7; 32]);
    assert_eq!(
        request.action,
        OperationActionV1::Send { request: original }
    );
}

#[test]
fn recipient_original_is_bound_to_the_genuine_signed_request_destination() {
    let request = request();
    request.verify(&scheme()).unwrap();
    let original = receiver_original();
    assert_eq!(
        send_destination_original(&original, &request).unwrap(),
        original
    );
    let (_, foreign) = account_original(0x53, Algorithm::Ed25519);
    assert!(send_destination_original(&foreign, &request).is_err());
    assert_eq!(
        request.body.receiver_account_digest,
        request.receiver_credential.body.account_digest
    );
    let mut retargeted = request.clone();
    retargeted.body.receiver_account_digest[0] ^= 1;
    assert!(retargeted.verify(&scheme()).is_err());
    assert!(send_destination_original(&original, &retargeted).is_err());
}

#[test]
fn unload_beneficiary_is_bound_to_the_genuine_signed_quote_before_review() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    let (beneficiary, original) = account_original(0x58, Algorithm::Ed25519);
    let certificate: KagemushaWalletSignerCertificateV1 =
        super::super::super::tests::fixture("KagemushaWalletSignerCertificateV1");
    let mut quote: KagemushaWalletChargeQuoteV1 =
        super::super::super::tests::fixture("KagemushaWalletChargeQuoteV1");
    quote.body.kind = KagemushaWalletChargeKindV1::Unload;
    quote.body.net_amount = 10;
    quote.body.online_charge = 1;
    quote.body.beneficiary_account_digest =
        kagemusha_wallet_account_digest_v1(&beneficiary).unwrap();
    // Public vector signer used solely for a real signature/binding component test.
    let all = vectors();
    let row = all["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some("regulator"))
        .unwrap();
    let signer =
        SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap()).unwrap();
    let signature: Signature = signer.sign(&quote.body.signing_message());
    let quote = KagemushaWalletChargeQuoteV1::sign(
        quote.body,
        &certificate,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    quote.verify(&scheme(), &certificate).unwrap();
    let charge = ChargeOriginalsV1 {
        quote: quote.to_canonical_bytes().unwrap(),
        certificates: archive::encode(
            &KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap(),
        )
        .unwrap(),
    };
    assert_eq!(
        unload_beneficiary_original(&scheme().scheme_id(), Some(&charge), Some(&original)).unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        unload_beneficiary_original(&scheme().scheme_id(), None, None).unwrap(),
        None
    );
    assert!(unload_beneficiary_original(&scheme().scheme_id(), Some(&charge), None).is_err());
    assert!(unload_beneficiary_original(&scheme().scheme_id(), None, Some(&original)).is_err());
    let mut trailing = original.clone();
    trailing.push(0);
    for invalid in [
        vec![],
        vec![0; ACCOUNT_ORIGINAL_MAX_BYTES_V1 + 1],
        trailing,
        account_original(0x59, Algorithm::Ed25519).1,
        account_original(0x5a, Algorithm::Secp256k1).1,
    ] {
        assert!(
            unload_beneficiary_original(&scheme().scheme_id(), Some(&charge), Some(&invalid))
                .is_err()
        );
    }
}

#[test]
fn recheck_preserves_the_private_unload_beneficiary_companion() {
    // Isolated private-capability comparison fixture; never an admitted wallet operation.
    let mut retained = unadmitted_review_fixture();
    retained.unload_beneficiary = Some(account_original(0x58, Algorithm::Ed25519).1);
    for substitute in [None, Some(account_original(0x59, Algorithm::Ed25519).1)] {
        let mut fresh = unadmitted_review_fixture();
        fresh.unload_beneficiary = substitute;
        assert!(matches!(
            retained.require_recheck(&fresh),
            Err(Error::OperationConflict)
        ));
    }
}

#[test]
fn recipient_original_rejects_bounds_noncanonical_and_unsupported_accounts() {
    let request = request();
    request.verify(&scheme()).unwrap();
    let original = receiver_original();
    let mut trailing = original.clone();
    trailing.push(0);
    let mut broken = original.clone();
    broken[0] ^= 1;
    for malformed in [
        vec![],
        vec![0; ACCOUNT_ORIGINAL_MAX_BYTES_V1 + 1],
        trailing,
        broken,
        norito::encode_canonical(&[0_u8; 32]).unwrap(),
    ] {
        assert!(send_destination_original(&malformed, &request).is_err());
    }
    let (secp, secp_original) = account_original(0x54, Algorithm::Secp256k1);
    let mut unsupported = request.clone();
    unsupported.body.receiver_account_digest = kagemusha_wallet_account_digest_v1(&secp).unwrap();
    // Even a matching digest cannot relax the existing single-Ed25519 account rule.
    assert!(send_destination_original(&secp_original, &unsupported).is_err());
    let members = [0x55, 0x56]
        .into_iter()
        .map(|seed| {
            let (account, _) = account_original(seed, Algorithm::Ed25519);
            MultisigMember::new(account.try_signatory().unwrap().clone(), 1).unwrap()
        })
        .collect();
    let multisig = AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
    unsupported.body.receiver_account_digest =
        kagemusha_wallet_account_digest_v1(&multisig).unwrap();
    assert!(
        send_destination_original(&norito::encode_canonical(&multisig).unwrap(), &unsupported)
            .is_err()
    );
}

#[test]
fn original_replacement_or_omission_cannot_pass_retained_review_recheck() {
    let review = unadmitted_review_fixture();
    for mutation in 0..3 {
        let mut fresh = unadmitted_review_fixture();
        match mutation {
            0 => fresh.projection.destination_account_original = None,
            1 => {
                fresh.projection.destination_account_original =
                    Some(account_original(0x57, Algorithm::Ed25519).1)
            }
            _ => fresh
                .projection
                .destination_account_original
                .as_mut()
                .unwrap()
                .push(0),
        }
        assert!(matches!(
            review.require_recheck(&fresh),
            Err(Error::OperationConflict)
        ));
    }
    let mut copied = review.projection().clone();
    copied
        .destination_account_original
        .as_mut()
        .unwrap()
        .fill(0);
    assert_eq!(
        review.projection().destination_account_original.as_deref(),
        Some(receiver_original().as_slice())
    );
    // Copying DATA supplies no constructor for the privately retained review/action.
    assert_ne!(copied, *review.projection());
}

#[test]
fn recheck_rejects_source_runtime_completion_generation_and_key_changes() {
    for mutation in 0..8 {
        let review = unadmitted_review_fixture();
        let mut fresh = unadmitted_review_fixture();
        review.require_recheck(&fresh).unwrap();
        match mutation {
            0 => fresh.source.archive_checkpoint[0] ^= 1,
            1 => fresh.source.artifact_manifest[0] ^= 1,
            2 => fresh.source.completion[0] ^= 1,
            3 => fresh.source.selected_generation += 1,
            4 => fresh.source.marker.wallet_id[0] ^= 1,
            5 => fresh.source.marker.payment_key = request().receiver_credential.body.payment_key,
            6 => fresh.projection.current_head[0] ^= 1,
            _ => fresh.projection.credential_digest[0] ^= 1,
        }
        assert!(matches!(
            review.require_recheck(&fresh),
            Err(Error::OperationConflict)
        ));
    }
}

#[test]
fn exact_review_action_rejects_retarget_and_false_fee_data_at_consumption() {
    let review = unadmitted_review_fixture();
    let mut changed = unadmitted_review_fixture();
    changed.projection.fee += 1;
    assert!(review.require_recheck(&changed).is_err());
    let mut changed = unadmitted_review_fixture();
    let OperationActionV1::Send { request } = &mut changed.action else {
        panic!("Send");
    };
    request[0] ^= 1;
    assert!(review.require_recheck(&changed).is_err());
    assert!(unadmitted_review_fixture().into_request([0; 32]).is_err());
}
