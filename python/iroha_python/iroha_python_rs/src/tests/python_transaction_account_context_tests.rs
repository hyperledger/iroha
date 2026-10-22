// Real native context tests included in the parent crypto boundary module.
fn context_account(seed: u8, prefix: u16) -> String {
    AccountId::new(PublicKey::from(parse_private_key(&[seed; 32]).unwrap()))
        .to_i105_for_discriminant(prefix).unwrap()
}
fn context_sponsor_fee(prefix: u16, seed: u8) -> String {
    format!(r#"{{"payer":"sponsor","value":{{"program_id":{{"sponsor":"{}","name":"retail"}},"program_revision":1,"charge_limits":[],"gas_limit":100}}}}"#,
        context_account(seed, prefix))
}
fn context_typed_instruction(prefix: u16) -> String {
    format!(r#"{{"name":"SetAssetHoldingLimit","params":{{"account_id":"{}","asset_definition_id":"66owaQmAQMuHxPzxUN3bqZ6FJfDa","holding_limit":"100"}}}}"#,
        context_account(0x51, prefix))
}
fn context_builder(prefix: u16) -> TransactionBuilder {
    let mut builder = TransactionBuilder::new(&python_test_network_id(),
        &context_account(0x51, prefix), &context_sponsor_fee(prefix, 0x52), prefix).unwrap();
    builder.set_creation_time_ms(42).unwrap();
    builder.set_ttl_ms(30000).unwrap();
    builder.set_nonce(7).unwrap();
    builder.add_instruction_json(&context_typed_instruction(prefix)).unwrap();
    builder
}

fn context_conditional_model() -> OpenConditionalEscrow {
    use iroha_data_model::escrow::{
        ConditionalEscrowCondition, ConditionalEscrowOracleCondition, ConditionalEscrowPredicate,
        ConditionalEscrowValue, ConditionalEscrowWithinCondition,
    };
    let account =
        |seed: u8| AccountId::new(PublicKey::from(parse_private_key(&[seed; 32]).unwrap()));
    OpenConditionalEscrow::new(
        iroha_data_model::escrow::EscrowId::new(iroha_crypto::Hash::new(
            b"selected-context-escrow",
        )),
        "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap(),
        account(0x54),
        iroha_primitives::numeric::Quantity::from(20_u64),
        vec![
            ConditionalEscrowCondition::Oracle(ConditionalEscrowOracleCondition {
                id: "product".parse().unwrap(),
                attestor: account(0x55),
                predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Text(
                    "i7".to_owned(),
                )),
                sequence: std::num::NonZeroU32::new(1).unwrap(),
            }),
            ConditionalEscrowCondition::Oracle(ConditionalEscrowOracleCondition {
                id: "delivery".parse().unwrap(),
                attestor: account(0x56),
                predicate: ConditionalEscrowPredicate::QuantityAtMost(
                    iroha_primitives::numeric::Quantity::from(259_200_u64),
                ),
                sequence: std::num::NonZeroU32::new(2).unwrap(),
            }),
            ConditionalEscrowCondition::Within(ConditionalEscrowWithinCondition {
                id: "confirmation".parse().unwrap(),
                duration_ms: std::num::NonZeroU64::new(604_800_000).unwrap(),
            }),
        ],
        604_800_042,
    )
}

fn context_conditional_conditions_json(prefix: u16) -> String {
    let _guard = ChainDiscriminantGuard::enter(prefix);
    json::to_json(&context_conditional_model().conditions).unwrap()
}

fn context_conditional_instruction(
    py: Python<'_>,
    prefix: u16,
    beneficiary: &str,
    conditions_json: &str,
    expires_at_ms: u64,
) -> PyResult<Instruction> {
    let conditions = py
        .import("json")?
        .call_method1("loads", (conditions_json,))?;
    Instruction::open_conditional_escrow(
        &py.get_type::<Instruction>(),
        py,
        "selected-context-escrow",
        "66owaQmAQMuHxPzxUN3bqZ6FJfDa",
        beneficiary,
        "20",
        &conditions,
        expires_at_ms,
        prefix,
        None,
    )
}

#[test]
fn conditional_escrow_account_context_preserves_independent_native_wire() {
    ensure_python();
    let ambient = iroha_data_model::account::address::chain_discriminant();
    let expected_model = context_conditional_model();
    let expected: InstructionBox = expected_model.clone().into();
    let expected_wire = norito::to_bytes(&expected).unwrap();
    Python::attach(|py| {
        for prefix in [117, 369, 753] {
            let conditions = context_conditional_conditions_json(prefix);
            for seed in [0x55, 0x56] {
                assert!(conditions.contains(&context_account(seed, prefix)));
            }
            let instruction = context_conditional_instruction(
                py,
                prefix,
                &context_account(0x54, prefix),
                &conditions,
                604_800_042,
            )
            .unwrap();
            let actual = instruction
                .inner
                .as_any()
                .downcast_ref::<OpenConditionalEscrow>()
                .expect("native conditional escrow instruction");
            assert_eq!(actual.beneficiary, expected_model.beneficiary);
            assert_eq!(actual.conditions, expected_model.conditions);
            assert_eq!(norito::to_bytes(&instruction.inner).unwrap(), expected_wire);
            assert_eq!(
                iroha_data_model::account::address::chain_discriminant(),
                ambient
            );
        }
    });
}

#[test]
fn conditional_escrow_account_context_rejects_each_foreign_identity() {
    ensure_python();
    Python::attach(|py| {
        for prefix in [117, 369, 753] {
            let beneficiary = context_account(0x54, prefix);
            let conditions = context_conditional_conditions_json(prefix);
            let before =
                context_conditional_instruction(py, prefix, &beneficiary, &conditions, 604_800_042)
                    .unwrap();
            let before_wire = norito::to_bytes(&before.inner).unwrap();
            for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
                assert!(
                    context_conditional_instruction(
                        py,
                        prefix,
                        &context_account(0x54, foreign),
                        &conditions,
                        604_800_042,
                    )
                    .is_err(),
                    "foreign scalar beneficiary must be rejected"
                );
                for seed in [0x55, 0x56] {
                    let changed = conditions.replace(
                        &context_account(seed, prefix),
                        &context_account(seed, foreign),
                    );
                    assert_ne!(changed, conditions);
                    assert!(
                        context_conditional_instruction(
                            py,
                            prefix,
                            &beneficiary,
                            &changed,
                            604_800_042,
                        )
                        .is_err(),
                        "foreign nested attestor {seed} must be rejected"
                    );
                }
            }
            for seed in [0x55, 0x56] {
                let malformed =
                    conditions.replace(&context_account(seed, prefix), "not-an-account");
                assert_ne!(malformed, conditions);
                assert!(
                    context_conditional_instruction(
                        py,
                        prefix,
                        &beneficiary,
                        &malformed,
                        604_800_042,
                    )
                    .is_err()
                );
            }
            let after =
                context_conditional_instruction(py, prefix, &beneficiary, &conditions, 604_800_042)
                    .unwrap();
            assert_eq!(norito::to_bytes(&before.inner).unwrap(), before_wire);
            assert_eq!(norito::to_bytes(&after.inner).unwrap(), before_wire);
        }
    });
}

#[test]
fn conditional_escrow_account_context_restores_outer_guard_on_every_exit() {
    ensure_python();
    let ambient = iroha_data_model::account::address::chain_discriminant();
    {
        let _outer = ChainDiscriminantGuard::enter(19);
        Python::attach(|py| {
            for prefix in [117, 369, 753] {
                let beneficiary = context_account(0x54, prefix);
                let conditions = context_conditional_conditions_json(prefix);
                assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
                context_conditional_instruction(py, prefix, &beneficiary, &conditions, 604_800_042)
                    .unwrap();
                assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
                let foreign = if prefix == 117 { 369 } else { 117 };
                let failures = [
                    (
                        context_account(0x54, foreign),
                        conditions.clone(),
                        604_800_042,
                    ),
                    (
                        beneficiary.clone(),
                        conditions.replace(
                            &context_account(0x55, prefix),
                            &context_account(0x55, foreign),
                        ),
                        604_800_042,
                    ),
                    (
                        beneficiary.clone(),
                        conditions.replace(
                            &context_account(0x56, prefix),
                            &context_account(0x56, foreign),
                        ),
                        604_800_042,
                    ),
                    (beneficiary.clone(), "[{}]".to_owned(), 604_800_042),
                    (beneficiary.clone(), conditions.clone(), 0),
                ];
                for (selected_beneficiary, selected_conditions, expiry) in failures {
                    assert!(
                        context_conditional_instruction(
                            py,
                            prefix,
                            &selected_beneficiary,
                            &selected_conditions,
                            expiry,
                        )
                        .is_err()
                    );
                    assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
                }
                context_conditional_instruction(py, prefix, &beneficiary, &conditions, 604_800_042)
                    .unwrap();
                assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
            }
        });
    }
    assert_eq!(
        iroha_data_model::account::address::chain_discriminant(),
        ambient
    );
}

#[test]
fn transaction_account_context_matrix_preserves_wire_and_all_envelope_paths() {
    ensure_python();
    let ambient = iroha_data_model::account::address::chain_discriminant();
    let mut reference_wire = None;
    for prefix in [117, 369, 753] {
        let mut builder = context_builder(prefix);
        let payload_json = builder.payload_json().unwrap();
        assert!(payload_json.contains(&context_account(0x51, prefix)));
        assert!(payload_json.contains(&context_account(0x52, prefix)));
        let mut quoted = builder.clone();
        let mut external = builder.clone();
        let ordinary = builder.sign(&[0x51; 32]).unwrap();
        let quoted = quoted.sign_quoted_payload(&payload_json, &context_sponsor_fee(prefix, 0x52), &[0x51; 32]).unwrap();
        let external = external.build_with_signature(&ordinary.signature).unwrap();
        assert_eq!(ordinary.authority, context_account(0x51, prefix));
        assert_eq!(ordinary.signed_transaction_versioned, quoted.signed_transaction_versioned);
        assert_eq!(ordinary.signed_transaction_versioned, external.signed_transaction_versioned);
        let reconstructed = signed_transaction_envelope_from_versioned_v1_py(
            &ordinary.signed_transaction_versioned, &python_test_network_id(), prefix).unwrap();
        assert_eq!(ordinary.authority, reconstructed.authority);
        let decoded = decode_canonical_signed_transaction_v1(&ordinary.signed_transaction_versioned).unwrap();
        // Privacy results use this identical authenticated renderer after proof admission.
        let shared = signed_transaction_envelope_from_model_v1(&decoded, prefix).unwrap();
        assert_eq!(ordinary.authority, shared.authority);
        if let Some(wire) = &reference_wire { assert_eq!(wire, &ordinary.signed_transaction_versioned); }
        else { reference_wire = Some(ordinary.signed_transaction_versioned.clone()); }
        Python::attach(|py| {
            let ty = py.get_type::<SignedTransactionEnvelope>();
            let json = ordinary.to_json().unwrap();
            let restored = SignedTransactionEnvelope::from_json(&ty, &json, prefix).unwrap();
            assert_eq!(restored.signed_transaction_versioned, ordinary.signed_transaction_versioned);
            for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
                assert!(SignedTransactionEnvelope::from_json(&ty, &json, foreign).is_err());
            }
        });
        assert_eq!(builder.chain_discriminant, prefix);
        builder.add_instruction_json(&context_typed_instruction(prefix)).unwrap();
        assert!(builder.payload_json().unwrap().contains(&context_account(0x52, prefix)));
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), ambient);
    }
}
#[test]
fn transaction_account_context_foreign_literals_and_quote_mutations_are_atomic() {
    ensure_python();
    for prefix in [117, 369, 753] {
        let mut builder = context_builder(prefix);
        let before = builder.payload_json().unwrap();
        for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
            assert!(TransactionBuilder::new(&python_test_network_id(), &context_account(0x51, foreign),
                &context_sponsor_fee(prefix, 0x52), prefix).is_err());
            assert!(builder.set_fee_payment_json(&context_sponsor_fee(foreign, 0x52)).is_err());
            assert!(builder.add_instruction_json(&context_typed_instruction(foreign)).is_err());
            assert!(builder.sign_quoted_payload(&before, &context_sponsor_fee(foreign, 0x52), &[0x51; 32]).is_err());
            let foreign_draft = before.replace(&context_account(0x51, prefix), &context_account(0x51, foreign));
            assert!(builder.sign_quoted_payload(&foreign_draft, &context_sponsor_fee(prefix, 0x52), &[0x51; 32]).is_err());
            assert_eq!(builder.payload_json().unwrap(), before);
        }
        for changed in [
            context_sponsor_fee(prefix, 0x53),
            context_sponsor_fee(prefix, 0x52).replace("\"program_revision\":1", "\"program_revision\":2"),
            context_sponsor_fee(prefix, 0x52).replace("retail", "other"),
            context_sponsor_fee(prefix, 0x52).replace("\"gas_limit\":100", "\"gas_limit\":101"),
            authority_fee_payment_json().to_owned(),
        ] {
            assert!(builder.sign_quoted_payload(&before, &changed, &[0x51; 32]).is_err());
            assert_eq!(builder.payload_json().unwrap(), before);
        }
        for field in ["creation_time_ms", "time_to_live_ms", "nonce"] {
            let mut altered: json::Value = json::from_str(&before).unwrap();
            altered.as_object_mut().unwrap().insert(field.into(), json::Value::from(999_u64));
            assert!(builder.sign_quoted_payload(&json::to_json(&altered).unwrap(), &context_sponsor_fee(prefix, 0x52), &[0x51; 32]).is_err());
            assert_eq!(builder.payload_json().unwrap(), before);
        }
        builder.sign(&[0x51; 32]).unwrap();
    }
}
#[test]
fn transaction_account_context_scoped_guards_restore_errors_unwinds_and_threads() {
    ensure_python();
    let ambient = iroha_data_model::account::address::chain_discriminant();
    {
        let _outer = ChainDiscriminantGuard::enter(19);
        let mut first = context_builder(117);
        let second = context_builder(369);
        for _ in 0..3 {
            assert!(first.payload_json().unwrap().contains(&context_account(0x51, 117)));
            assert!(second.payload_json().unwrap().contains(&context_account(0x51, 369)));
            assert!(first.set_fee_payment_json("{}").is_err());
            assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
        }
        let _ = std::panic::catch_unwind(|| {
            let _guard = ChainDiscriminantGuard::enter(369);
            panic!("controlled context unwinding");
        });
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 19);
        let handles: Vec<_> = [117, 369, 753].into_iter().map(|prefix| std::thread::spawn(move || {
            let own_ambient = iroha_data_model::account::address::chain_discriminant();
            assert!(context_builder(prefix).payload_json().unwrap().contains(&context_account(0x51, prefix)));
            assert_eq!(iroha_data_model::account::address::chain_discriminant(), own_ambient);
        })).collect();
        for handle in handles { handle.join().unwrap(); }
    }
    assert_eq!(iroha_data_model::account::address::chain_discriminant(), ambient);
}
#[test]
fn transaction_account_context_fee_factories_and_neutral_instruction_boundaries() {
    use iroha_data_model::nexus::{FeeSponsorEligibility, FeeSponsorRule, FeeSponsorRuleEffect,
        FeeSponsorRuleSelector, FeeSponsorNativeInstructionSelector, FeeSponsorAssetBudget,
        FeeSponsorMultisigSelector, FeeSponsorMultisigOperation};
    ensure_python();
    Python::attach(|py| {
        let ty = py.get_type::<Instruction>();
        for prefix in [117, 369, 753] {
            let sponsor = context_account(0x52, prefix);
            let beneficiary = context_account(0x51, prefix);
            let id = format!("{sponsor}/retail");
            let create = Instruction::create_fee_sponsor_program(&ty, &sponsor, &beneficiary, "retail", prefix).unwrap();
            let revision = FeeSponsorProgramRevision {
                program_id: FeeSponsorProgramId::new(parse_account_id(&sponsor).unwrap(), "retail".parse().unwrap()),
                revision: 1, eligibility: FeeSponsorEligibility::EnrolledOnly,
                rules: vec![FeeSponsorRule { id: "transfer".parse().unwrap(), effect: FeeSponsorRuleEffect::Allow,
                    selectors: vec![FeeSponsorRuleSelector::NativeInstruction(FeeSponsorNativeInstructionSelector {
                        wire_id: "iroha.transfer".into(), asset_definition_id: None,
                    }), FeeSponsorRuleSelector::Multisig(FeeSponsorMultisigSelector {
                        operations: vec![FeeSponsorMultisigOperation::Approve],
                        account_ids: vec![parse_account_id(&beneficiary).unwrap()],
                    })] }],
                asset_budgets: vec![FeeSponsorAssetBudget {
                    asset_definition_id: "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap(),
                    per_transaction: "1".parse().unwrap(), per_block: "10".parse().unwrap(),
                    per_program_epoch: "100".parse().unwrap(), per_beneficiary_epoch: "5".parse().unwrap(),
                    reserve_floor: "0".parse().unwrap(), epoch_length_blocks: NonZeroU64::new(100).unwrap(),
                }],
            };
            let revision_json = { let _guard = ChainDiscriminantGuard::enter(prefix); json::to_json(&revision).unwrap() };
            Instruction::stage_fee_sponsor_program_revision(&ty, &revision_json, prefix).unwrap();
            Instruction::activate_fee_sponsor_program_revision(&ty, &id, 1, 10, prefix).unwrap();
            Instruction::pause_fee_sponsor_program(&ty, &id, prefix).unwrap();
            Instruction::begin_close_fee_sponsor_program(&ty, &id, prefix).unwrap();
            Instruction::close_fee_sponsor_program(&ty, &id, prefix).unwrap();
            Instruction::enroll_fee_sponsor_beneficiary(&ty, &id, &beneficiary, prefix).unwrap();
            Instruction::unenroll_fee_sponsor_beneficiary(&ty, &id, &beneficiary, prefix).unwrap();
            Instruction::fund_fee_sponsor_program(&ty, &id, "66owaQmAQMuHxPzxUN3bqZ6FJfDa", "1", prefix).unwrap();
            Instruction::withdraw_fee_sponsor_program(&ty, &id, "66owaQmAQMuHxPzxUN3bqZ6FJfDa", "1", prefix).unwrap();
            let framed = norito::to_bytes(&create.inner).unwrap();
            let neutral = Instruction::from_norito_bytes(&ty, &framed).unwrap();
            assert_eq!(norito::to_bytes(&neutral.inner).unwrap(), framed);
            let mut appended = framed.clone(); appended.push(0);
            assert!(Instruction::from_norito_bytes(&ty, &appended).is_err());
            // Canonical identity bytes have no original display prefix to validate.
            for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
                let account = context_account(0x52, foreign);
                assert!(Instruction::create_fee_sponsor_program(&ty, &account, &beneficiary, "retail", prefix).is_err());
                assert!(Instruction::create_fee_sponsor_program(&ty, &sponsor, &account, "retail", prefix).is_err());
                assert!(Instruction::enroll_fee_sponsor_beneficiary(&ty, &id, &account, prefix).is_err());
                assert!(Instruction::unenroll_fee_sponsor_beneficiary(&ty, &id, &account, prefix).is_err());
                assert!(Instruction::pause_fee_sponsor_program(&ty, &format!("{account}/retail"), prefix).is_err());
                let foreign_program = format!("{account}/retail");
                assert!(Instruction::activate_fee_sponsor_program_revision(&ty, &foreign_program, 1, 10, prefix).is_err());
                assert!(Instruction::begin_close_fee_sponsor_program(&ty, &foreign_program, prefix).is_err());
                assert!(Instruction::close_fee_sponsor_program(&ty, &foreign_program, prefix).is_err());
                assert!(Instruction::fund_fee_sponsor_program(&ty, &foreign_program, "66owaQmAQMuHxPzxUN3bqZ6FJfDa", "1", prefix).is_err());
                assert!(Instruction::withdraw_fee_sponsor_program(&ty, &foreign_program, "66owaQmAQMuHxPzxUN3bqZ6FJfDa", "1", prefix).is_err());
                assert!(Instruction::stage_fee_sponsor_program_revision(&ty, &revision_json.replace(&sponsor, &account), prefix).is_err());
                assert!(Instruction::stage_fee_sponsor_program_revision(&ty, &revision_json.replace(&beneficiary, &context_account(0x51, foreign)), prefix).is_err());
                assert!(Instruction::from_json(&ty, &context_typed_instruction(foreign), prefix).is_err());
                let mut other = context_builder(foreign);
                other.add_instruction(&neutral).unwrap();
            }
            let typed = Instruction::from_json(&ty, &context_typed_instruction(prefix), prefix).unwrap();
            assert!(typed.inner.as_any().is::<SetAssetHoldingLimit>());
        }
    });
}

// These fixtures are constructed from native values for each selection before any
// hash or signature exists. No signed golden claim is rewritten to another prefix.
struct IndependentlyPreparedContextFixture {
    prefix: u16,
    operation: &'static str,
    authority: AccountId,
    target: AccountId,
    binding: json::Value,
    semantic_hash: String,
    context: json::Value,
    receipt: Option<json::Value>,
    signed: SignedTransaction,
}

fn prepared_fixture_object<const N: usize>(entries: [(&str, json::Value); N]) -> json::Value {
    json::Value::Object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn prepared_fixture_set(value: &mut json::Value, path: &[&str], replacement: json::Value) {
    let mut cursor = value;
    for field in &path[..path.len() - 1] {
        cursor = cursor.as_object_mut().unwrap().get_mut(*field).unwrap();
    }
    *cursor
        .as_object_mut()
        .unwrap()
        .get_mut(path[path.len() - 1])
        .unwrap() = replacement;
}

fn prepared_fixture_receipt_json(receipt: &PythonAccountOnboardingPlanReceiptV1) -> json::Value {
    // The verification DTOs intentionally implement Deserialize, not Serialize.
    // Public model fields still use native serializers; only the DTO envelope is assembled here.
    let body = &receipt.body;
    let request = prepared_fixture_object([
        ("version", json::to_value(&body.request.version).unwrap()),
        ("alias", json::to_value(&body.request.alias).unwrap()),
        (
            "account_id",
            json::to_value(&body.request.account_id).unwrap(),
        ),
        (
            "permissions",
            json::to_value(&body.request.permissions).unwrap(),
        ),
    ]);
    let body_json = prepared_fixture_object([
        ("version", json::to_value(&body.version).unwrap()),
        ("request", request),
        ("authority", json::to_value(&body.authority).unwrap()),
        ("network_id", json::to_value(&body.network_id).unwrap()),
        ("anchor", json::to_value(&body.anchor).unwrap()),
        ("resource", json::to_value(&body.resource).unwrap()),
        ("acquisition", json::to_value(&body.acquisition).unwrap()),
        ("quote_guard", json::to_value(&body.quote_guard).unwrap()),
        ("instructions", json::to_value(&body.instructions).unwrap()),
        (
            "owner_auto_renew_instruction",
            json::to_value(&body.owner_auto_renew_instruction).unwrap(),
        ),
        (
            "valid_until_ms",
            json::to_value(&body.valid_until_ms).unwrap(),
        ),
    ]);
    prepared_fixture_object([
        ("body", body_json),
        ("plan_hash", json::to_value(&receipt.plan_hash).unwrap()),
        ("signature", json::to_value(&receipt.signature).unwrap()),
    ])
}

impl IndependentlyPreparedContextFixture {
    fn new(prefix: u16, operation: &'static str) -> Self {
        use iroha_data_model::alias_setup::{
            AliasAccountIntentV1, AliasLeaseQuoteV1, ResolvedAccountAliasV1,
        };
        use norito::codec::Encode as _;

        let key = parse_private_key(&[0x61; 32]).unwrap();
        let authority = AccountId::new(PublicKey::from(key.clone()));
        let target = AccountId::new(PublicKey::from(parse_private_key(&[0x62; 32]).unwrap()));
        let target_literal = target.to_i105_for_discriminant(prefix).unwrap();
        let network = *python_test_network_id().as_inner();
        let definition: AssetDefinitionId = "4rPeAP6jAjiLVZThZYwwPRBuQagt".parse().unwrap();
        let deadline = 4_102_444_800_000_u64;
        let (context, receipt, semantic_hash, instructions) = match operation {
            "onboarding" => {
                let alias: AccountAliasName = "prefix-fixture@app.universal".parse().unwrap();
                let intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                    alias: ResolvedAccountAliasV1::new(alias.clone(), DataSpaceId::new(0)),
                    target_account: target.clone(),
                    provision: AccountProvisionV1::Create,
                    role: AccountAliasRoleV1::Primary,
                });
                let acquisition = AliasLeaseAcquisitionV1::new(1, None);
                let guard = AliasQuoteGuardV1 {
                    expected_policy_version: 1,
                    expected_payment_asset: definition.clone(),
                    max_amount: Quantity::from(10_u32),
                    valid_until_ms: deadline,
                };
                let ensure: InstructionBox = iroha_data_model::isi::alias_setup::EnsureAlias::new(
                    intent.clone(),
                    acquisition.clone(),
                    guard.clone(),
                )
                .into();
                let (wire_id, framed_payload) =
                    iroha_data_model::isi::framed_instruction_payload(&ensure).unwrap();
                let body = PythonAccountOnboardingPlanBodyV1 {
                    version: 1,
                    request: PythonAccountOnboardingPlanRequestV1 {
                        version: 1,
                        alias: alias.to_string(),
                        account_id: target_literal.clone(),
                        permissions: Vec::new(),
                    },
                    authority: authority.clone(),
                    network_id: network,
                    anchor: AliasPlanAnchorV1 {
                        block_height: 42,
                        block_hash: Hash::new(b"independent prepared fixture anchor"),
                    },
                    resource: AliasPlanResourceV1 {
                        intent: intent.clone(),
                        disposition: AliasPlanDispositionV1::Create,
                        quote: Some(AliasLeaseQuoteV1 {
                            target: intent.target(),
                            pricing_class: 1,
                            exact_amount: Quantity::from(5_u32),
                            guard: guard.clone(),
                            expires_at_ms: deadline + 1,
                            grace_expires_at_ms: deadline + 2,
                            redemption_expires_at_ms: deadline + 3,
                        }),
                        instruction_index: Some(0),
                    },
                    acquisition,
                    quote_guard: guard,
                    instructions: vec![AliasFramedInstructionV1 {
                        wire_id: wire_id.to_owned(),
                        framed_payload,
                    }],
                    owner_auto_renew_instruction: None,
                    valid_until_ms: deadline,
                };
                let plan_hash = body.canonical_hash();
                let receipt = PythonAccountOnboardingPlanReceiptV1 {
                    signature: Signature::new(&key, plan_hash.as_ref()),
                    body,
                    plan_hash,
                };
                // Serializers are guarded only synchronously, after native hashing/signing.
                let receipt_json = {
                    let _guard = ChainDiscriminantGuard::enter(prefix);
                    prepared_fixture_receipt_json(&receipt)
                };
                let context = prepared_fixture_object([
                    ("receipt", receipt_json.clone()),
                    ("account_id", json::Value::String(target_literal.clone())),
                    ("alias", json::Value::String(alias.to_string())),
                    (
                        "disposition",
                        json::to_value(&AliasPlanDispositionV1::Create).unwrap(),
                    ),
                ]);
                (
                    context,
                    Some(receipt_json),
                    hex_encode(plan_hash.as_ref()),
                    vec![ensure],
                )
            }
            "faucet" => {
                let claim = PythonAccountFaucetClaimV1 {
                    account_id: target_literal.clone(),
                    pow_anchor_height: 42,
                    pow_nonce_hex: "0001020304050607".to_owned(),
                };
                // Independent native encoding of the newly authored claim: do not
                // obtain the expected digest by calling the verification helper.
                let encoded = claim.encode();
                let semantic =
                    Hash::new_from_chunks(&[ACCOUNT_FAUCET_CLAIM_HASH_DOMAIN_V1, &encoded]);
                let claim_json = prepared_fixture_object([
                    ("account_id", json::Value::String(claim.account_id)),
                    (
                        "pow_anchor_height",
                        json::to_value(&claim.pow_anchor_height).unwrap(),
                    ),
                    ("pow_nonce_hex", json::Value::String(claim.pow_nonce_hex)),
                ]);
                let context = prepared_fixture_object([
                    ("claim", claim_json),
                    ("account_id", json::Value::String(target_literal.clone())),
                    (
                        "asset_definition_id",
                        json::Value::String(definition.to_string()),
                    ),
                    (
                        "asset_id",
                        json::Value::String(format!("{definition}#{target_literal}")),
                    ),
                    ("amount", json::to_value(&Quantity::from(5_u32)).unwrap()),
                ]);
                let instructions = vec![
                    InstructionBox::from(Register::account(Account::new(target.clone()))),
                    Transfer::asset_quantity(
                        AssetId::new(definition, authority.clone()),
                        5_u32,
                        target.clone(),
                    )
                    .into(),
                ];
                (context, None, hex_encode(semantic.as_ref()), instructions)
            }
            _ => panic!("closed prepared fixture operations"),
        };
        let binding = prepared_fixture_object([
            (
                "schema",
                json::Value::String("iroha.prepared-operation.binding.v1".to_owned()),
            ),
            (
                "semantic_hash_hex",
                json::Value::String(semantic_hash.clone()),
            ),
            ("kind", json::Value::String(operation.to_owned())),
            ("request_id", json::Value::String("ab".repeat(32))),
            (
                "execution_expires_at_unix_ms",
                json::to_value(&deadline).unwrap(),
            ),
        ]);
        let mut metadata = Metadata::default();
        metadata.insert(
            "prepared_operation_binding".parse::<Name>().unwrap(),
            Json::from_norito_value_ref(&binding).unwrap(),
        );
        metadata.insert(
            "prepared_operation".parse::<Name>().unwrap(),
            Json::new(operation.to_owned()),
        );
        metadata.insert(
            "prepared_semantic_hash".parse::<Name>().unwrap(),
            Json::new(semantic_hash.clone()),
        );
        if operation == "faucet" {
            metadata.insert(
                iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY
                    .parse::<Name>()
                    .unwrap(),
                Json::new(iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1),
            );
        }
        let mut builder = ModelTransactionBuilder::new(
            network,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_instructions(instructions);
        builder.set_creation_time(Duration::from_millis(4_000_000_000_000));
        builder.set_ttl(Duration::from_secs(3_600));
        builder.set_nonce(NonZeroU32::new(7).unwrap());
        let signed = builder.sign(&key);
        Self {
            prefix,
            operation,
            authority,
            target,
            binding,
            semantic_hash,
            context,
            receipt,
            signed,
        }
    }

    fn verify_with(
        &self,
        prefix: u16,
        authority: &str,
        binding: &json::Value,
        context: &json::Value,
        wire: &[u8],
    ) -> PyResult<SignedTransactionEnvelope> {
        verify_prepared_transaction_context_v1_py(
            wire,
            &python_test_network_id(),
            authority,
            &json::to_json(binding).unwrap(),
            self.operation,
            &self.semantic_hash,
            &json::to_json(&FeePaymentIntent::authority(Vec::new(), None)).unwrap(),
            &json::to_json(context).unwrap(),
            prefix,
        )
    }
}

#[test]
fn independently_signed_prepared_context_matrix_binds_exact_selected_claims() {
    ensure_python();
    let ambient = iroha_data_model::account::address::chain_discriminant();
    for operation in ["onboarding", "faucet"] {
        let fixtures: Vec<_> = [117, 369, 753]
            .into_iter()
            .map(|prefix| IndependentlyPreparedContextFixture::new(prefix, operation))
            .collect();
        // The account text is part of the semantic claim, so independently authored
        // prefixes produce different valid signatures/hashes, not equal wire claims.
        for pair in fixtures.windows(2) {
            assert_ne!(pair[0].semantic_hash, pair[1].semantic_hash);
            assert_ne!(pair[0].signed.hash(), pair[1].signed.hash());
            assert_eq!(pair[0].signed.instructions(), pair[1].signed.instructions());
        }
        for index in [0, 1, 2, 0, 2, 1] {
            let fixture = &fixtures[index];
            let prefix = fixture.prefix;
            let authority = fixture.authority.to_i105_for_discriminant(prefix).unwrap();
            let target = fixture.target.to_i105_for_discriminant(prefix).unwrap();
            let wire = fixture.signed.encode_wire_v1().unwrap();
            fixture.signed.verify_signature().unwrap();
            let verified = fixture
                .verify_with(
                    prefix,
                    &authority,
                    &fixture.binding,
                    &fixture.context,
                    &wire,
                )
                .unwrap();
            assert_eq!(verified.authority, authority);
            assert_eq!(verified.signed_transaction_versioned, wire);
            assert_eq!(
                canonical_signed_transaction_hash_v1(&wire).unwrap(),
                *fixture.signed.hash().as_ref()
            );
            let restored = signed_transaction_envelope_from_versioned_v1_py(
                &wire,
                &python_test_network_id(),
                prefix,
            )
            .unwrap();
            assert_eq!(restored.to_json().unwrap(), verified.to_json().unwrap());
            if let Some(receipt) = &fixture.receipt {
                let hash = verify_account_onboarding_receipt_v1_py(
                    &json::to_json(receipt).unwrap(),
                    &python_test_network_id(),
                    &authority,
                    &target,
                    "prefix-fixture@app.universal",
                    "[]",
                    prefix,
                )
                .unwrap();
                assert_eq!(hash, fixture.semantic_hash);
                let mut tampered = receipt.clone();
                prepared_fixture_set(
                    &mut tampered,
                    &["body", "anchor", "block_height"],
                    json::to_value(&43_u64).unwrap(),
                );
                assert!(
                    verify_account_onboarding_receipt_v1_py(
                        &json::to_json(&tampered).unwrap(),
                        &python_test_network_id(),
                        &authority,
                        &target,
                        "prefix-fixture@app.universal",
                        "[]",
                        prefix
                    )
                    .is_err()
                );
            }
            for foreign in [117, 369, 753].into_iter().filter(|value| *value != prefix) {
                // Both foreign supplied pins and a foreign independently selected
                // context fail; universal controller equality is insufficient.
                let foreign_authority =
                    fixture.authority.to_i105_for_discriminant(foreign).unwrap();
                assert!(
                    fixture
                        .verify_with(
                            prefix,
                            &foreign_authority,
                            &fixture.binding,
                            &fixture.context,
                            &wire
                        )
                        .is_err()
                );
                assert!(
                    fixture
                        .verify_with(
                            foreign,
                            &authority,
                            &fixture.binding,
                            &fixture.context,
                            &wire
                        )
                        .is_err()
                );
                assert!(
                    fixture
                        .verify_with(
                            foreign,
                            &foreign_authority,
                            &fixture.binding,
                            &fixture.context,
                            &wire
                        )
                        .is_err()
                );
                let foreign_target = fixture.target.to_i105_for_discriminant(foreign).unwrap();
                let mut substituted = fixture.context.clone();
                prepared_fixture_set(
                    &mut substituted,
                    &["account_id"],
                    json::Value::String(foreign_target.clone()),
                );
                assert!(
                    fixture
                        .verify_with(prefix, &authority, &fixture.binding, &substituted, &wire)
                        .is_err()
                );
                // Even a consistently rewritten presentation cannot retain the
                // original receipt signature or semantic hash.
                let rewritten = json::to_json(&fixture.context)
                    .unwrap()
                    .replace(&target, &foreign_target)
                    .replace(&authority, &foreign_authority);
                let rewritten: json::Value = json::from_json(&rewritten).unwrap();
                assert!(
                    fixture
                        .verify_with(
                            foreign,
                            &foreign_authority,
                            &fixture.binding,
                            &rewritten,
                            &wire
                        )
                        .is_err()
                );
                if let Some(receipt) = &fixture.receipt {
                    assert!(
                        verify_account_onboarding_receipt_v1_py(
                            &json::to_json(receipt).unwrap(),
                            &python_test_network_id(),
                            &authority,
                            &target,
                            "prefix-fixture@app.universal",
                            "[]",
                            foreign
                        )
                        .is_err()
                    );
                    assert!(
                        verify_account_onboarding_receipt_v1_py(
                            &json::to_json(receipt).unwrap(),
                            &python_test_network_id(),
                            &authority,
                            &foreign_target,
                            "prefix-fixture@app.universal",
                            "[]",
                            prefix
                        )
                        .is_err()
                    );
                }
            }
            let mut wrong_binding = fixture.binding.clone();
            prepared_fixture_set(
                &mut wrong_binding,
                &["request_id"],
                json::Value::String("cd".repeat(32)),
            );
            assert!(
                fixture
                    .verify_with(prefix, &authority, &wrong_binding, &fixture.context, &wire)
                    .is_err()
            );
            let mut expired_binding = fixture.binding.clone();
            prepared_fixture_set(
                &mut expired_binding,
                &["execution_expires_at_unix_ms"],
                json::to_value(&4_000_000_000_001_u64).unwrap(),
            );
            assert!(
                fixture
                    .verify_with(
                        prefix,
                        &authority,
                        &expired_binding,
                        &fixture.context,
                        &wire
                    )
                    .is_err()
            );
            let mut wrong_operation = fixture.context.clone();
            if operation == "faucet" {
                prepared_fixture_set(
                    &mut wrong_operation,
                    &["amount"],
                    json::to_value(&Quantity::from(6_u32)).unwrap(),
                );
            } else {
                prepared_fixture_set(
                    &mut wrong_operation,
                    &["disposition"],
                    json::to_value(&AliasPlanDispositionV1::Conflict).unwrap(),
                );
            }
            assert!(
                fixture
                    .verify_with(
                        prefix,
                        &authority,
                        &fixture.binding,
                        &wrong_operation,
                        &wire
                    )
                    .is_err()
            );
            let mut noncanonical_wire = wire.clone();
            noncanonical_wire.push(0);
            assert!(
                fixture
                    .verify_with(
                        prefix,
                        &authority,
                        &fixture.binding,
                        &fixture.context,
                        &noncanonical_wire
                    )
                    .is_err()
            );
            assert_eq!(
                fixture
                    .verify_with(
                        prefix,
                        &authority,
                        &fixture.binding,
                        &fixture.context,
                        &wire
                    )
                    .unwrap()
                    .signed_transaction_versioned,
                wire
            );
            assert_eq!(
                iroha_data_model::account::address::chain_discriminant(),
                ambient
            );
        }
    }
}
