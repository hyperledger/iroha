//! Pure conversion/differential fixtures, never installed proof or custody authority.

use super::*;
use ff::Field;
use iroha_kagemusha_proof::{
    controls::{QuotaSend, evaluate_quota},
    tree::{INDEXED_NODE_DOMAIN, path_root},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fn state() -> KagemushaWalletStateV1 {
    let f = |value| Fp::from(value).to_repr();
    KagemushaWalletStateV1 {
        version: 1,
        core: KagemushaWalletStateCoreV1 {
            lifecycle: KagemushaWalletLifecycleV1::Retiring,
            scheme_id: core::array::from_fn(|i| i as u8 + 1),
            asset_digest: [2; 32],
            wallet_id: [3; 32],
            credential_digest: f(7),
            balance: u128::MAX - 10,
            burned_total: 19,
            sequence: 23,
            next_send: 29,
            next_load: 31,
            next_redeem: 37,
            send_chain: f(41),
            recv_chain: f(43),
            consumed_credit_root: f(47),
            pending_outgoing_root: f(53),
            load_redeem_recovery_root: f(59),
            fee_claim_root: f(61),
            quota_usage_root: f(67),
            enabled_controls: 7,
            quota_windows_root: f(71),
            quota_share_expires_at_ms: 73,
            blacklist_version: 79,
            blacklist_root: f(83),
            blacklist_issued_at_ms: 89,
            blacklist_max_age_ms: 97,
            time_anchor_max_response_ms: 101,
            lease_expires_at_ms: 103,
            policy_epoch: 107,
            accepted_time_floor_ms: 109,
            state_nonce: f(113),
        },
        rest: KagemushaWalletStateRestV1 {
            permitted_controls: 7,
            scheme_policy: f(127),
            fee_schedule: f(131),
            blacklist: f(137),
            quota_share: f(139),
            quota_share_id: 149,
            time_anchor: f(151),
            blacklist_history_root: f(157),
        },
    }
}

fn body() -> KagemushaWalletRequestBodyV1 {
    let f = |value| Fp::from(value).to_repr();
    KagemushaWalletRequestBodyV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        payer_wallet_id: [3; 32],
        payer_account_digest: core::array::from_fn(|i| i as u8 + 1),
        receiver_wallet_id: [4; 32],
        receiver_account_digest: core::array::from_fn(|i| i as u8 + 33),
        send_ordinal: 5,
        receiver_credential_digest: f(7),
        amount: 11,
        fee_schedule: f(13),
        fee: 17,
        policy_epoch: 19,
        scheme_policy: f(23),
        receiver_accepted_time_ms: 29,
        receiver_blacklist_version: 31,
        receiver_blacklist_root: f(37),
        certificates: f(41),
        nonce: [43; 32],
    }
}

#[test]
fn complete_current_state_projection_matches_model_core_rest_and_commitment() {
    let original = state();
    let native = state_fields(&original).unwrap();
    assert_eq!(
        native.core.fields(),
        fields::<33>(original.core_field_items().unwrap()).unwrap()
    );
    assert_eq!(
        native.rest.fields::<Fp>(),
        fields::<8>(original.rest_field_items().unwrap()).unwrap()
    );
    assert_eq!(
        native.commitment().to_repr(),
        original.commitment().unwrap().value
    );
    assert_eq!(
        native.core.roots.load_redeem_recovery.to_repr(),
        original.core.load_redeem_recovery_root
    );
    let mut malformed = original;
    malformed.rest.time_anchor = [0xff; 32];
    assert_eq!(state_fields(&malformed), Err(Error::Authority));
    let mut malformed = original;
    malformed.core.state_nonce = [0; 32];
    assert_eq!(state_fields(&malformed), Err(Error::Authority));
}

#[test]
fn request_projection_preserves_both_account_limbs_nonce_and_historical_selector() {
    let original = body();
    let native = request_fields(&original).unwrap();
    assert_eq!(
        native.fields::<Fp>(),
        fields::<26>(original.field_items()).unwrap()
    );
    assert_eq!(native.credit_id::<Fp>().to_repr(), original.credit_id());
    for receiver in [true, false] {
        for index in [0, 16] {
            let mut changed = original;
            if receiver {
                changed.receiver_account_digest[index] ^= 1;
            } else {
                changed.payer_account_digest[index] ^= 1;
            }
            assert_ne!(
                request_fields(&changed).unwrap().credit_id::<Fp>(),
                native.credit_id::<Fp>()
            );
        }
    }
    let mut none = original;
    none.receiver_blacklist_version = 0;
    none.receiver_blacklist_root = [0; 32];
    assert_eq!(
        request_fields(&none)
            .unwrap()
            .terms
            .receiver_blacklist_version,
        0
    );
    let mut malformed = original;
    malformed.receiver_blacklist_root = [0xff; 32];
    assert_eq!(request_fields(&malformed), Err(Error::Authority));
}

#[test]
fn genuine_receive_evaluator_preserves_quoted_credential_and_current_controls() {
    for enabled_controls in 0..=7 {
        let mut source = state();
        source.core.balance = 100;
        source.core.enabled_controls = enabled_controls;
        let mut original = body();
        original.scheme_id = source.core.scheme_id;
        original.asset_digest = source.core.asset_digest;
        original.payer_wallet_id = [4; 32];
        original.receiver_wallet_id = source.core.wallet_id;
        original.receiver_credential_digest = Fp::from(211).to_repr();
        original.receiver_blacklist_version = 0;
        original.receiver_blacklist_root = [0; 32];
        let request = request_fields(&original).unwrap();
        let witness = StepWitness {
            relation_id: [5; 32],
            predecessor: state_fields(&source).unwrap(),
            successor_nonce: Fp::from(223),
            inputs: StepInputs::Receive(Box::new(ReceiveInputs {
                payer_wallet: request.payer_wallet,
                payer_account_digest: request.payer_account,
                receiver_account_digest: request.receiver_account,
                send_ordinal: request.send_ordinal,
                receiver_credential_digest: request.receiver_credential_digest,
                request: request.terms,
                successor_consumed_credit: Fp::from(227),
                blacklist: BlacklistGap::unused(),
            })),
        };
        assert_ne!(
            request.receiver_credential_digest,
            source.core.credential_digest
        );
        assert_eq!(witness.request_body(), request);
        let effect = KagemushaWalletEffectV1::Receive {
            credit_id: original.credit_id(),
            payer_wallet_id: original.payer_wallet_id,
            amount: original.amount,
        };
        let (next, statement) = derive(&source, SigmaRelation::RECEIVE, &witness, effect).unwrap();
        assert_eq!(next.core.enabled_controls, enabled_controls);
        assert_eq!(statement.enabled_controls, enabled_controls);
        assert_eq!(SigmaRelation::RECEIVE.enabled_controls(), 0);
        assert_eq!(next.core.balance, 111);
        assert_eq!(next.core.next_send, source.core.next_send);
        assert_eq!(next.core.burned_total, source.core.burned_total);
        assert_eq!(next.rest, source.rest);
        assert_eq!(next.core.state_nonce, Fp::from(223).to_repr());
        let wrong = KagemushaWalletEffectV1::Receive {
            credit_id: original.credit_id(),
            payer_wallet_id: original.payer_wallet_id,
            amount: original.amount + 1,
        };
        assert_eq!(
            derive(&source, SigmaRelation::RECEIVE, &witness, wrong),
            Err(Error::Authority)
        );
    }
}

#[test]
fn actual_depth32_model_insert_preserves_all_native_path_values() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    let old = tree.root();
    let key = Fp::from(233).to_repr();
    let value = Fp::from(239).to_repr();
    let original = tree.insert(key, value).unwrap();
    let new = original.verify(&old, &key, &value).unwrap();
    let converted = insertion(&original).unwrap();
    assert_eq!(
        path_root(
            INDEXED_NODE_DOMAIN,
            converted.leaf.hash(),
            u64::from(converted.leaf_slot),
            &converted.leaf_siblings
        )
        .to_repr(),
        old
    );
    let mut linked = converted.leaf;
    linked.next_key = word(key).unwrap();
    let intermediate = path_root(
        INDEXED_NODE_DOMAIN,
        linked.hash(),
        u64::from(converted.leaf_slot),
        &converted.leaf_siblings,
    );
    assert_eq!(
        path_root(
            INDEXED_NODE_DOMAIN,
            Fp::ZERO,
            u64::from(converted.slot),
            &converted.slot_siblings
        ),
        intermediate
    );
    let inserted = IndexedLeaf {
        key: word(key).unwrap(),
        value: word(value).unwrap(),
        next_key: converted.leaf.next_key,
    };
    assert_eq!(
        path_root(
            INDEXED_NODE_DOMAIN,
            inserted.hash(),
            u64::from(converted.slot),
            &converted.slot_siblings
        )
        .to_repr(),
        new
    );
    let mut malformed = original;
    malformed.low_opening.siblings[31] = [0xff; 32];
    assert_eq!(insertion(&malformed), Err(Error::Authority));
}

#[test]
fn quota_segments_use_complete_signed_windows_and_running_actual_usage_paths() {
    let windows = vec![
        KagemushaWalletQuotaWindowV1 {
            kind: KagemushaWalletQuotaWindowKindV1::Daily,
            start_ms: 100,
            end_ms: 200,
            limit: 100,
        },
        KagemushaWalletQuotaWindowV1 {
            kind: KagemushaWalletQuotaWindowKindV1::Daily,
            start_ms: 200,
            end_ms: 300,
            limit: 100,
        },
        KagemushaWalletQuotaWindowV1 {
            kind: KagemushaWalletQuotaWindowKindV1::Monthly,
            start_ms: 100,
            end_ms: 1000,
            limit: 100,
        },
    ];
    let root = kagemusha_wallet_quota_windows_root_v1(&windows).unwrap();
    // This signature is a codec fixture only; it is never admitted as an authentic share.
    let signer = SigningKey::from_slice(&[7; 32]).unwrap();
    let signature: Signature = signer.sign(b"pure quota projection fixture");
    let signature = signature.normalize_s().unwrap_or(signature);
    let share = KagemushaWalletQuotaShareV1 {
        body: KagemushaWalletQuotaShareBodyV1 {
            version: 1,
            scheme_id: [1; 32],
            asset_digest: [2; 32],
            wallet_id: [3; 32],
            share_id: 1,
            issued_at_ms: 50,
            expires_at_ms: 1000,
            windows_root: root,
            window_count: 3,
            signer_certificate: Fp::from(5).to_repr(),
        },
        windows: windows.clone(),
        signature: KagemushaDeviceSignatureV1::from_raw_bytes(signature.to_bytes().as_slice())
            .unwrap(),
    };
    let before = KagemushaWalletQuotaUsageArrayV1::zero_for(&windows).unwrap();
    let mut running = before;
    let mut charges = Vec::new();
    for slot in 0_u8..3 {
        let leaf = running.leaf(slot).unwrap();
        charges.push(KagemushaWalletQuotaChargeV1 {
            window: windows[usize::from(slot)],
            window_opening: kagemusha_wallet_quota_window_opening_v1(&windows, slot).unwrap(),
            usage: leaf,
            usage_opening: running.opening(slot).unwrap(),
        });
        let mut slots = *running.slots();
        slots[usize::from(slot)] = Some(KagemushaWalletQuotaUsageLeafV1 {
            used: leaf.used + 7,
            ..leaf
        });
        running = KagemushaWalletQuotaUsageArrayV1::from_slots(slots).unwrap();
    }
    let check = KagemushaWalletSendCheckV1 {
        interval: KagemushaWalletTimeIntervalV1 {
            lower_ms: 150,
            upper_ms: 210,
        },
        effect: KagemushaWalletEffectV1::Retiring,
        blacklist_gap: None,
        quota_charges: charges,
        quota_usage: running,
    };
    let converted = quota(
        SigmaRelation::send(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1),
        Some(&share),
        &check,
    )
    .unwrap();
    assert_eq!(
        [converted.segments[0].base, converted.segments[1].base],
        [0, 2]
    );
    assert_eq!(
        [
            converted.charges[0].slot,
            converted.charges[1].slot,
            converted.charges[2].slot
        ],
        [0, 1, 2]
    );
    let outcome = evaluate_quota(
        &converted,
        &QuotaSend {
            windows_root: word(root).unwrap(),
            usage_root: word(before.root()).unwrap(),
            lower: 150,
            upper: 210,
            gross: Fp::from(7),
            gross_integer: Some(7),
        },
    );
    assert!(outcome.violations.is_empty(), "{:?}", outcome.violations);
    assert_eq!(outcome.usage_root.to_repr(), running.root());
    let mut missing = check.clone();
    missing.quota_charges.pop();
    assert_eq!(
        quota(SigmaRelation::send(2), Some(&share), &missing),
        Err(Error::Authority)
    );
    let mut changed = share;
    changed.windows[0].end_ms += 1;
    assert_eq!(
        quota(SigmaRelation::send(2), Some(&changed), &check),
        Err(Error::Authority)
    );
}

#[test]
fn receive_result_proposals_bind_exact_burn_and_overflow() {
    assert_eq!(proposed_receive_burn(9, 11, &[true; 5], false).unwrap(), 9);
    assert_eq!(proposed_receive_burn(9, 11, &[true; 5], true).unwrap(), 20);
    assert!(proposed_receive_burn(u128::MAX, 1, &[true; 5], true).is_err());
    for owner in 0..5 {
        let mut results = [true; 5];
        results[owner] = false;
        assert_eq!(proposed_receive_burn(9, 11, &results, false).unwrap(), 20);
        assert!(proposed_receive_burn(u128::MAX, 1, &results, false).is_err());
    }
    assert_eq!(
        proposed_receive_burn(u128::MAX, 1, &[true; 5], false).unwrap(),
        u128::MAX
    );
}

#[test]
fn receive_credit_route_preserves_first_and_binds_inserted_burn() {
    for burned in [false, true] {
        let mut tree = KagemushaWalletIndexedTreeV1::default();
        let old = tree.root();
        let entry = KagemushaWalletCreditDigestLeafV1 {
            credit_id: Fp::from(7).to_repr(),
            payment_digest: Fp::from(9).to_repr(),
            burned,
        };
        let record = entry.record(&mut tree).unwrap();
        receive_credit_route(record, &old, &tree.root(), &entry).unwrap();
        let changed = KagemushaWalletCreditDigestLeafV1 {
            burned: !burned,
            ..entry
        };
        assert!(receive_credit_route(record, &old, &tree.root(), &changed).is_err());
        let changed = KagemushaWalletCreditDigestLeafV1 {
            payment_digest: Fp::from(10).to_repr(),
            ..changed
        };
        let present = changed.record(&mut tree).unwrap();
        assert!(matches!(
            present,
            KagemushaWalletCreditDigestRecordV1::Present { .. }
        ));
        receive_credit_route(present, &tree.root(), &tree.root(), &changed).unwrap();
        assert!(receive_credit_route(present, &tree.root(), &old, &changed).is_err());
    }
}
