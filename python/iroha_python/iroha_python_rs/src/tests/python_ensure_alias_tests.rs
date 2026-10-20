// Exact native alias construction: no planner-provided InstructionBox dispatch.
fn ensure_alias_fixture() -> (
    Vec<AliasIntentV1>,
    AliasLeaseAcquisitionV1,
    AliasQuoteGuardV1,
) {
    use iroha_data_model::alias_setup::{
        AliasAccountIntentV1, AliasDataSpaceIntentV1, AliasDomainIntentV1, ResolvedAccountAliasV1,
        ResolvedDataSpaceV1, ResolvedDomainV1,
    };
    let owner = sample_account(0x71);
    let intents = vec![
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new("universal".parse().unwrap(), DataSpaceId::new(0)),
            owner: owner.clone(),
        }),
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(
                iroha_model_base::domain::DomainId::try_new("app", "universal").unwrap(),
                DataSpaceId::new(0),
            ),
            owner: owner.clone(),
        }),
        AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(
                "owner@app.universal".parse().unwrap(),
                DataSpaceId::new(0),
            ),
            target_account: owner,
            provision: AccountProvisionV1::Create,
            role: AccountAliasRoleV1::Primary,
        }),
    ];
    (
        intents,
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: 1,
            expected_payment_asset: "4rPeAP6jAjiLVZThZYwwPRBuQagt".parse().unwrap(),
            max_amount: Quantity::from(10_u32),
            valid_until_ms: 4_102_444_800_000,
        },
    )
}

fn ensure_alias_documents(
    intent: &AliasIntentV1,
    acquisition: &AliasLeaseAcquisitionV1,
    quote_guard: &AliasQuoteGuardV1,
    prefix: u16,
) -> [String; 3] {
    let _guard = ChainDiscriminantGuard::enter(prefix);
    [
        json::to_json(intent).unwrap(),
        json::to_json(acquisition).unwrap(),
        json::to_json(quote_guard).unwrap(),
    ]
}

fn ensure_alias_expected_bytes(
    intent: AliasIntentV1,
    acquisition: AliasLeaseAcquisitionV1,
    quote_guard: AliasQuoteGuardV1,
) -> Vec<u8> {
    let instruction: InstructionBox =
        iroha_data_model::isi::alias_setup::EnsureAlias::new(intent, acquisition, quote_guard)
            .into();
    norito::to_bytes(&instruction).unwrap()
}

#[test]
fn ensure_alias_native_constructor_matches_typed_models_across_prefixes() {
    ensure_python();
    let _outer = ChainDiscriminantGuard::enter(19);
    let (intents, acquisition, quote_guard) = ensure_alias_fixture();
    Python::attach(|py| {
        let ty = py.get_type::<Instruction>();
        for intent in intents {
            let expected =
                ensure_alias_expected_bytes(intent.clone(), acquisition, quote_guard.clone());
            for prefix in [117, 369, 753] {
                let [intent_json, acquisition_json, guard_json] =
                    ensure_alias_documents(&intent, &acquisition, &quote_guard, prefix);
                let instruction = Instruction::ensure_alias(
                    &ty,
                    &intent_json,
                    &acquisition_json,
                    &guard_json,
                    prefix,
                )
                .unwrap();
                assert_eq!(instruction.wire_id().unwrap(), "iroha.alias.ensure");
                assert_eq!(norito::to_bytes(&instruction.inner).unwrap(), expected);
                assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
            }
        }
    });
}

#[test]
fn ensure_alias_native_constructor_preserves_each_selected_component() {
    ensure_python();
    let (intents, acquisition, quote_guard) = ensure_alias_fixture();
    let intent = intents[2].clone();
    let baseline = ensure_alias_expected_bytes(intent.clone(), acquisition, quote_guard.clone());
    let mut variants = Vec::new();
    // Every alias binding is independently selected by the caller.
    for field in 0..5 {
        let mut changed = intent.clone();
        let AliasIntentV1::AccountAlias(account) = &mut changed else {
            unreachable!()
        };
        match field {
            0 => account.alias.canonical_name = "other@app.universal".parse().unwrap(),
            1 => account.alias.dataspace_id = DataSpaceId::new(12),
            2 => account.target_account = sample_account(0x72),
            3 => account.provision = AccountProvisionV1::Existing,
            4 => account.role = AccountAliasRoleV1::Additional,
            _ => unreachable!(),
        }
        variants.push((changed, acquisition, quote_guard.clone()));
    }
    variants.push((
        intent.clone(),
        AliasLeaseAcquisitionV1::new(2, None),
        quote_guard.clone(),
    ));
    variants.push((
        intent.clone(),
        AliasLeaseAcquisitionV1::new(1, Some(2)),
        quote_guard.clone(),
    ));
    // A planner cannot substitute a different quote cap, asset, policy, or expiry.
    for field in 0..4 {
        let mut changed = quote_guard.clone();
        match field {
            0 => changed.expected_policy_version = 2,
            1 => changed.expected_payment_asset = "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap(),
            2 => changed.max_amount = Quantity::from(11_u32),
            3 => changed.valid_until_ms += 1,
            _ => unreachable!(),
        }
        variants.push((intent.clone(), acquisition, changed));
    }
    Python::attach(|py| {
        let ty = py.get_type::<Instruction>();
        for (intent, acquisition, quote_guard) in variants {
            let expected =
                ensure_alias_expected_bytes(intent.clone(), acquisition, quote_guard.clone());
            assert_ne!(expected, baseline);
            let [intent_json, acquisition_json, guard_json] =
                ensure_alias_documents(&intent, &acquisition, &quote_guard, 369);
            let instruction =
                Instruction::ensure_alias(&ty, &intent_json, &acquisition_json, &guard_json, 369)
                    .unwrap();
            assert_eq!(norito::to_bytes(&instruction.inner).unwrap(), expected);
        }
    });
}

#[test]
fn ensure_alias_native_constructor_rejects_substitution_and_foreign_prefixes() {
    ensure_python();
    let _outer = ChainDiscriminantGuard::enter(19);
    let (intents, acquisition, quote_guard) = ensure_alias_fixture();
    Python::attach(|py| {
        let ty = py.get_type::<Instruction>();
        for intent in intents {
            for prefix in [117, 369, 753] {
                let documents = ensure_alias_documents(&intent, &acquisition, &quote_guard, prefix);
                for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
                    assert!(
                        Instruction::ensure_alias(
                            &ty,
                            &documents[0],
                            &documents[1],
                            &documents[2],
                            foreign,
                        )
                        .is_err()
                    );
                }
                // A wrapped instruction or swapped component is never an alias intent.
                let wrapped = format!(
                    r#"{{"name":"EnsureAlias","params":{{"intent":{},"acquisition":{},"quote_guard":{}}}}}"#,
                    documents[0], documents[1], documents[2],
                );
                for bad_intent in [
                    wrapped.as_str(),
                    r#"{"wire_id":"iroha.transfer","framed_payload":"00"}"#,
                    documents[1].as_str(),
                ] {
                    assert!(
                        Instruction::ensure_alias(
                            &ty,
                            bad_intent,
                            &documents[1],
                            &documents[2],
                            prefix,
                        )
                        .is_err()
                    );
                }
                for index in 0..3 {
                    let mut substituted = documents.clone();
                    let mut value: json::Value = json::from_str(&substituted[index]).unwrap();
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("unselected".into(), json::Value::Null);
                    substituted[index] = json::to_json(&value).unwrap();
                    assert!(
                        Instruction::ensure_alias(
                            &ty,
                            &substituted[0],
                            &substituted[1],
                            &substituted[2],
                            prefix,
                        )
                        .is_err()
                    );
                }
                for (bad_acquisition, bad_guard) in [
                    (r#"{"term_years":1}"#, documents[2].as_str()),
                    (documents[2].as_str(), documents[1].as_str()),
                ] {
                    assert!(
                        Instruction::ensure_alias(
                            &ty,
                            &documents[0],
                            bad_acquisition,
                            bad_guard,
                            prefix,
                        )
                        .is_err()
                    );
                }
                assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
            }
        }
    });
}
