#[test]
fn register_restricted_asset_definition_requires_explicit_owning_domain() {
    // Exercise the missing domain independently of the earlier alias namespace guard.
    // The aliased case must still refuse before publishing either definition or alias.
    for with_alias in [false, true] {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let definition_id = AssetDefinitionId::from_uuid_bytes([
            0x8a, 0xb5, 0xec, 0x8c, 0x32, 0xdf, 0x46, 0xcf, 0x87, 0xca, 0x3e, 0xd9, 0xce, 0x36,
            0xa8, 0x19,
        ])
        .expect("opaque asset definition id");
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("dataspace-root alias");
        let definition = AssetDefinition::numeric(
            definition_id.clone(),
            "unit".to_owned(),
            AssetBalancePolicy::DataspaceRestricted,
            None,
        )
        .with_alias(with_alias.then(|| alias.clone()));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        tx.current_dataspace_id = Some(paynet);
        tx.world.current_dataspace_id = Some(paynet);
        let error = Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect_err("restricted definitions must not omit authoritative domain context");
        assert!(
            error.to_string().contains(if with_alias {
                "a restricted dataspace namespace cannot alias another dataspace"
            } else {
                "requires an explicit owning domain"
            }),
            "unexpected error: {error}"
        );
        assert!(tx.world.asset_definitions.get(&definition_id).is_none());
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
        assert!(
            tx.world
                .asset_definition_direct_homes
                .get(&definition_id)
                .is_none()
        );
        assert!(
            tx.world
                .asset_definition_domains
                .get(&definition_id)
                .is_none()
        );
    }
}
