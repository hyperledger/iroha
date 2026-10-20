// Required funded-turnstile layout and exact restored backing controls.

#[test]
fn funded_reserve_record_roundtrips_without_reset_and_rejects_missing_allowance() {
    let fixture = orchard_persisted_fixture();
    let state = fixture.state();
    let id = AssetId::with_scope(
        state.asset_definition_id().clone(),
        state.reserve_account().clone(),
        state.public_balance_scope(),
    );
    let owner = PrivacyPublicReserveOwnerV1::Orchard {
        namespace: fixture.namespace,
        bootstrap_digest: fixture.bootstrap_digest,
    };
    let mut record = PrivacyStateItemRecordV1::public_reserve_custody(id.clone(), owner).unwrap();
    assert_eq!(
        record.public_reserve_funded_allowance(),
        Some(&Quantity::zero())
    );
    let PrivacyStateItemRecordV1::PublicReserveCustody {
        funded_allowance, ..
    } = &mut record
    else {
        unreachable!()
    };
    *funded_allowance = Quantity::from(7_u32);
    record.validate().unwrap();
    assert_eq!(record.public_reserve_custody_ref(), Some((&id, owner)));
    super::super::frame_test_support::assert_owner_frame_v1(
        &record,
        "iroha_core::privacy_state::PrivacyStateItemRecordV1",
    );
    let encoded = json::to_json(&record).unwrap();
    let restored: PrivacyStateItemRecordV1 = json::from_json(&encoded).unwrap();
    assert_eq!(restored, record);
    assert_eq!(
        restored.public_reserve_funded_allowance(),
        Some(&Quantity::from(7_u32))
    );
    let missing = encoded
        .replace("\"funded_allowance\":\"7\",", "")
        .replace(",\"funded_allowance\":\"7\"", "");
    assert_ne!(missing, encoded);
    assert!(
        json::from_json::<PrivacyStateItemRecordV1>(&missing).is_err(),
        "no old-layout zero fallback"
    );
    for invalid in ["-1", "07", "not-a-quantity"] {
        let changed = encoded.replacen(
            "\"funded_allowance\":\"7\"",
            &format!("\"funded_allowance\":\"{invalid}\""),
            1,
        );
        assert_ne!(changed, encoded);
        assert!(json::from_json::<PrivacyStateItemRecordV1>(&changed).is_err());
    }
}

#[test]
fn funded_reserve_restore_keeps_bootstrap_identity_and_requires_exact_backing() {
    let mut fixture = orchard_persisted_fixture();
    let state = fixture.state();
    let id = AssetId::with_scope(
        state.asset_definition_id().clone(),
        state.reserve_account().clone(),
        state.public_balance_scope(),
    );
    let owner = PrivacyPublicReserveOwnerV1::Orchard {
        namespace: fixture.namespace,
        bootstrap_digest: fixture.bootstrap_digest,
    };
    let key = PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &id).unwrap();
    fixture.commitments.insert(
        key.clone(),
        PrivacyStateItemRecordV1::PublicReserveCustody {
            reserve_asset_id: id.clone(),
            owner,
            funded_allowance: Quantity::from(7_u32),
        },
    );
    fixture
        .validate()
        .expect("bootstrap comparison is immutable identity, not a zero allowance reconstruction");
    let json = json::to_json(&fixture.commitments).unwrap();
    fixture.commitments = json::from_json(&json).unwrap();
    fixture.validate().unwrap();
    let mut accounts = Storage::<AccountId, ()>::new();
    accounts.insert(id.account().clone(), ());
    let mut definitions = Storage::<AssetDefinitionId, ()>::new();
    definitions.insert(id.definition().clone(), ());
    let mut assets = Storage::<AssetId, AssetValue>::new();
    for balance in [None, Some(6_u32)] {
        if let Some(balance) = balance {
            assets.insert(id.clone(), AssetValue::new(Quantity::from(balance)));
        }
        assert_eq!(
            validate_privacy_public_reserve_dependencies_v1(
                &fixture.commitments.view(),
                &accounts.view(),
                &definitions.view(),
                &assets.view()
            )
            .unwrap_err(),
            "privacy public reserve funded allowance exceeds its exact balance"
        );
        assert_eq!(
            fixture
                .commitments
                .view()
                .get(&key)
                .unwrap()
                .public_reserve_funded_allowance(),
            Some(&Quantity::from(7_u32))
        );
    }
    assets.insert(id.clone(), AssetValue::new(Quantity::from(7_u32)));
    validate_privacy_public_reserve_dependencies_v1(
        &fixture.commitments.view(),
        &accounts.view(),
        &definitions.view(),
        &assets.view(),
    )
    .unwrap();
    {
        let mut block = assets.block();
        let removed = block
            .remove(id.clone())
            .expect("exact reserve asset exists");
        assert_eq!(removed.as_ref(), &Quantity::from(7_u32));
        block.commit();
    }
    assert!(assets.view().get(&id).is_none());
    let other_scope = match id.scope() {
        AssetBalanceScope::Global => {
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::new(9))
        }
        _ => AssetBalanceScope::Global,
    };
    assets.insert(
        AssetId::with_scope(id.definition().clone(), id.account().clone(), other_scope),
        AssetValue::new(Quantity::from(100_u32)),
    );
    assert!(
        validate_privacy_public_reserve_dependencies_v1(
            &fixture.commitments.view(),
            &accounts.view(),
            &definitions.view(),
            &assets.view()
        )
        .is_err(),
        "another physical scope cannot back this allowance"
    );
    assets.insert(id, AssetValue::new(Quantity::from(8_u32)));
    validate_privacy_public_reserve_dependencies_v1(
        &fixture.commitments.view(),
        &accounts.view(),
        &definitions.view(),
        &assets.view(),
    )
    .unwrap();
}
