//! Explicit canonical policy authoring, duplicate refusal and signed-source binding.

use super::*;

fn authored_policy() -> CryptoAdmissionPolicyV1 {
    CryptoAdmissionPolicyV1::new(vec![
        Algorithm::Ed25519,
        Algorithm::Secp256k1,
        Algorithm::BlsNormal,
    ])
    .expect("this fixture explicitly selects three canonical algorithms")
}

fn manifest(policy: CryptoAdmissionPolicyV1) -> RawGenesisTransaction {
    init_instruction_registry();
    GenesisBuilder::new_without_executor(ChainId::from("explicit-policy-producer"), ".", policy)
        .with_staking_policy(crate::staking_policy_authoring::fixture_policy())
        .expect("explicit fixture staking policy")
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .set_topology(deterministic_test_genesis_topology_entries())
        .build_raw()
        .expect("explicit complete genesis source")
}

fn policy_slots(batches: &[Vec<InstructionBox>]) -> Vec<&CustomParameter> {
    batches
        .iter()
        .flatten()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set| match set.inner() {
            Parameter::Custom(custom)
                if custom.id() == &CryptoAdmissionPolicyV1::parameter_id() =>
            {
                Some(custom)
            }
            _ => None,
        })
        .collect()
}

#[test]
fn explicit_policy_survives_raw_json_normalization_signing_and_authenticated_validation()
-> Result<()> {
    let policy = authored_policy();
    let original = manifest(policy.clone()).with_consensus_meta()?;
    let text = norito::json::to_json(&original)?;
    let decoded: RawGenesisTransaction = norito::json::from_str(&text)?;
    assert_eq!(decoded.crypto_admission_policy(), &policy);
    let encoded = norito::to_bytes(&decoded)?;
    let binary_decoded: RawGenesisTransaction = norito::decode_from_bytes(&encoded)?;
    assert_eq!(binary_decoded.crypto_admission_policy(), &policy);
    let normalized = decoded.clone().normalize()?;
    assert_eq!(normalized.crypto_admission_policy, policy);
    let slots = policy_slots(&normalized.transactions);
    assert_eq!(slots.len(), 1);
    let Parameter::Custom(expected_parameter) = policy.clone().into_parameter()? else {
        unreachable!()
    };
    assert_eq!(slots[0].payload(), expected_parameter.payload());
    assert_eq!(
        CryptoAdmissionPolicyV1::from_payload(slots[0].payload())?,
        policy
    );
    let key = KeyPair::from_seed(vec![0x81; 32], Algorithm::Ed25519);
    let block = decoded
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            &key, None, None, 1_000,
        )?
        .0;
    let signed_batches = block
        .external_transactions()
        .map(|tx| match tx.instructions() {
            Executable::Instructions(instructions) => instructions.to_vec(),
            _ => panic!("genesis must preserve explicit instructions"),
        })
        .collect::<Vec<_>>();
    let signed_slots = policy_slots(&signed_batches);
    assert_eq!(signed_slots.len(), 1);
    assert_eq!(signed_slots[0], slots[0]);
    let wire = block.encode_wire()?;
    validate_prepared_genesis_bundle(&wire, &decoded, key.public_key(), block.hash())?;
    let changed = decoded
        .into_builder()
        .with_crypto_admission_policy(CryptoAdmissionPolicyV1::new(vec![Algorithm::Secp256k1])?)
        .build_raw()?;
    assert!(
        validate_prepared_genesis_bundle(&wire, &changed, key.public_key(), block.hash()).is_err()
    );
    Ok(())
}

#[test]
fn missing_policy_and_retired_crypto_manifest_have_no_decode_fallback() -> Result<()> {
    let value = norito::json::value::to_value(&manifest(authored_policy()))?;
    let mut fields = value.as_object().unwrap().clone();
    let mut dual_fields = fields.clone();
    dual_fields.insert(
        "crypto".into(),
        norito::json!({"allowed_signing":["ed25519"]}),
    );
    let dual_error = norito::json::value::from_value::<RawGenesisTransaction>(
        norito::json::Value::Object(dual_fields),
    )
    .expect_err("retired crypto field is unknown beside the required canonical policy");
    assert!(dual_error.to_string().contains("crypto"));
    fields.remove("crypto_admission_policy");
    let missing = norito::json::Value::Object(fields.clone());
    assert!(norito::json::value::from_value::<RawGenesisTransaction>(missing).is_err());
    fields.insert(
        "crypto".into(),
        norito::json!({"allowed_signing":["ed25519"]}),
    );
    assert!(
        norito::json::value::from_value::<RawGenesisTransaction>(norito::json::Value::Object(
            fields
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_or_noncanonical_authored_lists_are_never_normalized() -> Result<()> {
    for list in [
        r#"[]"#,
        r#"["ed25519","ed25519"]"#,
        r#"["secp256k1","ed25519"]"#,
        r#"["unknown"]"#,
    ] {
        let mut fields = norito::json::value::to_value(&manifest(authored_policy()))?
            .as_object()
            .unwrap()
            .clone();
        fields.insert(
            "crypto_admission_policy".into(),
            norito::json::parse_value(&format!("{{\"allowed_algorithms\":{list}}}"))?,
        );
        assert!(
            norito::json::value::from_value::<RawGenesisTransaction>(norito::json::Value::Object(
                fields
            ))
            .is_err(),
            "{list}"
        );
    }
    Ok(())
}

#[test]
fn root_signing_trust_does_not_insert_an_ordinary_ed25519_exemption() -> Result<()> {
    let policy = CryptoAdmissionPolicyV1::new(vec![Algorithm::Secp256k1])?;
    let original = manifest(policy.clone()).with_consensus_meta()?;
    let key = KeyPair::from_seed(vec![0x82; 32], Algorithm::Ed25519);
    let block = original
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            &key, None, None, 1_000,
        )?
        .0;
    validate_prepared_genesis_bundle(
        &block.encode_wire()?,
        &original,
        key.public_key(),
        block.hash(),
    )?;
    assert_eq!(original.crypto_admission_policy(), &policy);
    assert!(!policy.allows(Algorithm::Ed25519));
    Ok(())
}

#[test]
fn known_policy_members_do_not_depend_on_this_producers_crypto_backend() -> Result<()> {
    let policy = CryptoAdmissionPolicyV1::new(Algorithm::ALL.to_vec())?;
    let source = manifest(policy.clone());
    let batches = source.parse()?;
    let slots = policy_slots(&batches);
    assert_eq!(slots.len(), 1);
    assert_eq!(
        CryptoAdmissionPolicyV1::from_payload(slots[0].payload())?,
        policy
    );
    Ok(())
}

#[test]
fn equal_and_conflicting_instructions_in_every_source_batch_are_rejected() -> Result<()> {
    for source_index in [0, 1, 3] {
        for duplicate in [
            authored_policy(),
            CryptoAdmissionPolicyV1::new(vec![Algorithm::Secp256k1])?,
        ] {
            let mut original = manifest(authored_policy());
            while original.transactions.len() <= source_index {
                original.transactions.push(RawGenesisTx::default());
            }
            original.transactions[source_index]
                .instructions
                .push(SetParameter::new(duplicate.clone().into_parameter()?).into());
            let error = original
                .parse()
                .expect_err("field and same-ID instruction always duplicate authority");
            assert_eq!(
                error.to_string(),
                RawGenesisTransaction::explicit_set_parameter_message(source_index, 0),
                "direct instructions are rejected at the existing earlier structural boundary"
            );
            let mut structured = manifest(authored_policy());
            let mut parameters = structured.transactions[0].parameters.take().unwrap();
            parameters.set_parameter(duplicate.into_parameter()?);
            while structured.transactions.len() <= source_index {
                structured.transactions.push(RawGenesisTx::default());
            }
            structured.transactions[source_index].parameters = Some(parameters);
            let error = structured
                .parse()
                .expect_err("the sole structured parameter block cannot repeat field authority");
            assert!(
                error.to_string().contains("duplicates its authority"),
                "{error:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn builder_cannot_collapse_duplicate_policy_assignments_before_validation() -> Result<()> {
    for late in [false, true] {
        let mut builder = GenesisBuilder::new_without_executor(
            ChainId::from("duplicate-policy"),
            ".",
            authored_policy(),
        )
        .with_staking_policy(crate::staking_policy_authoring::fixture_policy())
        .expect("explicit fixture staking policy")
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended());
        if late {
            builder = builder.next_transaction();
        }
        let result = builder
            .append_parameter(authored_policy().into_parameter()?)
            .build_raw();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicates its authority")
        );
    }
    Ok(())
}

#[test]
fn policy_field_and_public_manifest_reader_preserve_actual_local_refusal_and_retry() -> Result<()> {
    let policy = CryptoAdmissionPolicyV1::new(Algorithm::ALL.to_vec())?;
    let value = norito::json::value::to_value(&policy)?;
    let source = manifest(policy.clone());
    let bytes = norito::json::to_vec(&source)?;
    let before = bytes.clone();
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let field_error = zero
        .with(|| {
            RawGenesisTransaction::decode_value::<CryptoAdmissionPolicyV1>(
                value.clone(),
                "crypto_admission_policy",
            )
        })
        .expect_err("the actual policy list reader needs decoder allowance");
    let field_identity = match &field_error {
        norito::json::Error::ScopedDecodeResource(original) => original.clone(),
        other => panic!("the original scoped policy refusal must not become a message: {other:?}"),
    };
    let attempt = norito::core::classify_decode_attempt(|| {
        Err::<CryptoAdmissionPolicyV1, _>(norito::Error::Json(field_error))
    })
    .unwrap_err();
    let original = attempt
        .into_local_refusal()
        .expect("original policy reader owner");
    let expected = norito::core::classify_decode_attempt(|| {
        Err::<(), _>(norito::Error::ScopedDecodeResource(field_identity))
    })
    .unwrap_err()
    .into_local_refusal()
    .unwrap();
    assert_eq!(original, expected);
    let public_error = zero
        .with(|| {
            RawGenesisTransaction::from_json_slice_at_path(
                &bytes,
                Path::new("/explicit-source/genesis.json"),
            )
        })
        .expect_err("the public actual manifest reader also refuses locally");
    assert!(
        public_error
            .downcast_ref::<norito::json::Error>()
            .is_some_and(|error| error.is_decode_resource_limit()),
        "the public path context must preserve the original JSON error source: {public_error:?}"
    );
    assert_eq!(
        RawGenesisTransaction::decode_value::<CryptoAdmissionPolicyV1>(
            value,
            "crypto_admission_policy"
        )?,
        policy
    );
    let retried = RawGenesisTransaction::from_json_slice_at_path(
        &bytes,
        Path::new("/explicit-source/genesis.json"),
    )?;
    assert_eq!(retried.crypto_admission_policy(), &policy);
    assert_eq!(bytes, before);
    Ok(())
}
